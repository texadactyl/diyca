"""
bob: SSL server
"""
import os
import select
import socket
import sys
import signal
import configparser
from OpenSSL import SSL, crypto

import utilities as util

MYNAME = "bob"
SECTION_NAME = "everything"
MAX_RECEIVE_SIZE = 2048

readers = {}  # fd list for reading, initially, nil
writers = {}  # fd list for writing, initially, nil
dummies = {}  # Nil list for handling exceptions, never changes

def server_application(arg_inbound_msg):
    """
    Very simple server application:
        simply return the input message as the output message (echo)
    """
    return arg_inbound_msg

def remove_key(xsocket, err=None):
    """
    Remove a list-key (socked file descriptor in Linux-speak) from both
    the readers and writers lists.
    Then, shutdown and close the socket
    """
    if err:
        util.logger("Client {%s} left unexpectedly, reason: {%s}", xsocket.getpeername(), repr(err))
    else:
        util.logger("Client {%s} left politely", xsocket.getpeername())
    del readers[xsocket]
    if xsocket in writers:
        del writers[xsocket]
    try:
        if not err:
            xsocket.shutdown()
        xsocket.close()
    except Exception as exc:
        util.logger("Socket shutdown or close failed, reason: {%s}", repr(exc))

def closer(arg_exit_code):
    """
    Close any open client sockets.
    Close the server/listener socket.
    Exit to operating system.
    """
    # For any readers still around, close them down
    for csocket in readers.keys():
        try:
            peer = csocket.getpeername()
            csocket.close()
            util.logger("closer: rsocket for peer {%s} closed", peer)
        except Exception as err:
            util.logger("closer: rsocket.close() error for peer {%s}, reason: {%s}",
                        csocket.getpeername(), repr(err))
    # Close down server/listener socket
    try:
        server.close()
    except Exception as exc:
        util.logger("closer: server.close() error, reason: {%s}", repr(exc))
    util.logger("closer: Bye bye")
    sys.exit(arg_exit_code)

def signal_handler(arg_signal, arg_frame):
    """
    Catch termination signals
    """
    util.logger("signal_handler: Caught signal {%d}", arg_signal)
    closer(86)

def examine_certificate(arg_conn, arg_cert, arg_errnum, arg_depth, arg_ok):
    """
    Examine the incoming client certificate.
    """
    subject = crypto.X509Name(arg_cert.get_subject())
    common_name = subject.commonName
    util.logger("Received certificate from client CN={%s}, depth={%d}", common_name, arg_depth)
    return 1

#------------ Begin Main Program ------------------------------------
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python   bob.py   configuration-file")
        sys.exit(86)
    config_file = sys.argv[1]
    if not os.path.isfile(config_file):
        util.oops("Cannot access config file {%s}", config_file)
    try:
        config = configparser.ConfigParser()
        config.read(config_file)
        my_crt_file = os.path.abspath(config.get(SECTION_NAME, "my_crt_file"))
        if len(my_crt_file) < 1:
            util.oops("This is not a config file: {%s}", config_file)
        util.logger(f"my_crt_file: {my_crt_file}")
        my_key_file = os.path.abspath(config.get(SECTION_NAME, "my_key_file"))
        util.logger(f"my_key_file: {my_key_file}")
        ca_crt_file = os.path.abspath(config.get(SECTION_NAME, "ca_crt_file"))
        util.logger(f"ca_crt_file: {ca_crt_file}")
        my_port = config.getint(SECTION_NAME, "my_port")
        util.logger(f"my_port: {my_port}")
        session_timeout = config.getint(SECTION_NAME, "session_timeout")
    except Exception as exc:
        util.oops("Trouble with config file {%s}, reason: {%s}", config_file, repr(exc))

    # Initialize context
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                   examine_certificate)         # Demand a client certificate
    ctx.use_certificate_file(my_crt_file)       # Provide a server certificate
    ctx.use_privatekey_file(my_key_file)        # My private key
    ctx.load_verify_locations(ca_crt_file)      # I trust this CA
    ctx.set_timeout(session_timeout)            # Set session timeout value
    util.logger("SSL context initialized")

    # Set up server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server = SSL.Connection(ctx, sock)
        server.bind(("localhost", my_port))
        server.listen(3)
        server.setblocking(0)  # non-blocking
    except Exception as exc:
        util.oops("Cannot start listening for SSL connections to port {%d}, reason: {%s}",
                  my_port, repr(exc))
    util.logger("SSL server socket initialized")

    # Catch termination signals
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    #======================= MAIN LOOP ========================================
    while True:
        # Verbose! util.logger("Top of main loop")
        try:
            rready, wready, dummy = select.select([server] + list(readers.keys()),
                                                  list(writers.keys()),
                                                  dummies)
        except Exception as exc:
            util.logger("Caught an exception in select.select(), reason: {%s}", repr(exc))
            break
        # Process all of the sockets that are ready to receive
        for rsocket in rready:
            if rsocket == server:
                rsocket, addr = server.accept()
                util.logger("Connection received from {%s}", rsocket.getpeername())
                readers[rsocket] = addr

            else:
                try:
                    msg = rsocket.recv(MAX_RECEIVE_SIZE).decode('utf-8')
                except (SSL.WantReadError,
                        SSL.WantWriteError,
                        SSL.WantX509LookupError):
                    util.logger("Ignored error on rsocket from {%s}", rsocket.getpeername())
                except SSL.ZeroReturnError:
                    remove_key(rsocket)
                except SSL.Error as exc:
                    remove_key(rsocket, exc)
                except:
                    util.oops("Mysterious exception on rsocket from {%s}", rsocket.getpeername())
                else:
                    # msg = message from client on rsocket
                    if rsocket not in writers:
                        # Verbose! util.logger("Initializing a writer socket for rsocket from {%s}", rsocket.getpeername())
                        writers[rsocket] = ""
                    # This inbound message (msg) has an associated writer-socket
                    # Have the server_application produce a response
                    #    and schedule it for transmission
                    writers[rsocket] = writers[rsocket] + server_application(msg)

        # Process all of the sockets that are ready to transmit
        for wsocket in wready:
            try:
                nbytes_sent = wsocket.send(str.encode(writers[wsocket]))
            except (SSL.WantReadError,
                    SSL.WantWriteError,
                    SSL.WantX509LookupError):
                util.logger("Ignored error on wsocket from {%s}", wsocket.getpeername())
            except SSL.ZeroReturnError:
                remove_key(wsocket)
            except SSL.Error as exc:
                remove_key(wsocket, exc)
            except:
                util.oops("Mysterious exception on wsocket from {%s}", wsocket.getpeername())
            else:
                # msg partially transmitted by send()
                # Trim down message by the number of bytes sent
                writers[wsocket] = writers[wsocket][nbytes_sent:]
                # If done, delete socket from writers list
                if writers[wsocket] == "":
                    del writers[wsocket]

    #================== End ====================================================
    closer(0)
