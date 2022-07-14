"""
alice: SSL client
"""

import os
import socket
import sys
import time
import configparser
from OpenSSL import SSL, crypto

import utilities as util

MYNAME = "alice"
SECTION_NAME = "everything"
MAX_RECEIVE = 2048

def examine_certificate(arg_conn, arg_cert, arg_errnum, arg_depth, arg_okay):
    """
    Examine the incoming server certificate
    Unused input: arg_conn, arg_errnum, arg_okay
    """
    subject = crypto.X509Name(arg_cert.get_subject())
    common_name = subject.commonName
    util.logger("Received certificate from server CN={%s}, depth={%d}", common_name, arg_depth)
    return 1

#------------ Begin Main Program ------------------------------------
if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Usage: python   alice.py   configuration-file   transmit-text-file")
        sys.exit(86)
    config_file = sys.argv[1]
    input_file = sys.argv[2]
    if not os.path.isfile(config_file):
        util.oops("Cannot access config file {%s}", config_file)
    try:
        config = configparser.ConfigParser()
        config.read(config_file)
        my_crt_file = config.get(SECTION_NAME, "my_crt_file")
        if len(my_crt_file) < 1:
            util.oops("This is not a config file: {%s}", config_file)
        my_key_file = os.path.abspath(config.get(SECTION_NAME, "my_key_file"))
        util.logger(f"my_key_file: {my_key_file}")
        ca_crt_file = os.path.abspath(config.get(SECTION_NAME, "ca_crt_file"))
        util.logger(f"ca_crt_file: {ca_crt_file}")
        server_addr = config.get(SECTION_NAME, "server_addr")
        util.logger(f"server_addr: {server_addr}")
        server_port = config.getint(SECTION_NAME, "server_port")
        util.logger(f"server_port: {server_port}")
        session_timeout = config.getint(SECTION_NAME, "session_timeout")
        flag_verbose = config.getboolean(SECTION_NAME, "flag_verbose")
    except Exception as err:
        util.oops("Trouble with config file {%s}, reason: {%s}", config_file, repr(err))

    # Initialize context
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                   examine_certificate)         # Demand a client certificate
    ctx.use_certificate_file(my_crt_file)       # Provide a server certificate
    ctx.use_privatekey_file(my_key_file)        # My private key
    ctx.load_verify_locations(ca_crt_file)      # I trust this CA
    ctx.set_timeout(session_timeout)            # Set session timeout value
    util.logger("SSL context initialized")


    # Set up client connection to server
    try:
        util.logger("Server @ {%s:%d}", server_addr, server_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = SSL.Connection(ctx, sock)
        conn.connect((server_addr, server_port))

    except Exception as err:
        util.oops("Cannot create an SSL connection to {%s:%d}, reason: {%s}",
                  server_addr, server_port, repr(err))

    # Open input file
    fd = None
    try:
        fd = open(input_file, "r")
    except Exception as err:
        util.oops("Cannot open file {%s}, reason: {%s}", input_file, repr(err))

    #======================= MAIN LOOP ========================================
    counter = 0
    tstart = time.time()
    while True:
        try:
            outline = fd.readline()
            if not outline:
                break   # EOF
            outline = outline.rstrip('\n')
            if outline == "":
                outline = " "
        except Exception as err:
            util.oops("Cannot readline() with file {%s}, reason: {%s}", input_file, repr(err))
        try:
            conn.send(str.encode(outline))
            if flag_verbose:
                util.logger("Sent{%d}: {%s}", counter, outline)
            if counter == 0:
                util.logger("Ciphers in use: {%s}, secret key nbits: {%s}, SSL/TLS version: {%s}",
                            conn.get_cipher_name(),
                            conn.get_cipher_bits(),
                            conn.get_cipher_version())
            inline = (conn.recv(MAX_RECEIVE)).decode('utf-8')
            counter = counter + 1
            if flag_verbose:
                util.logger("Received{%d}: {%s}", counter, inline)
        except SSL.Error as err:
            util.oops("SSL Connection died unexpectedly, reason: {%s}", repr(err))
    tstop = time.time()
    deltat = tstop - tstart

    #================== End ====================================================
    util.logger("Processed {%d} lines of input file {%s}", counter, input_file)
    util.logger("Elapsed time = {%d} seconds", deltat)
    conn.shutdown()
    conn.close()
    fd.close()
