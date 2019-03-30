'''
	DIYCA Web Server Signer (Surrogate for Calvin)
	Use Calvin's private key and certificate
'''

import os
import uuid
from OpenSSL import crypto
from flask import current_app as app

CA_CRT_FILE = "../certs/diyca_calvin.crt"
CA_KEY_FILE = "../calvin/private/diyca_calvin.key"
EXPIRY_PERIOD = 60*60*24*365*2   # 2 years
DIGEST = "sha256"

#=================================================================
# Retrieve the contents of a file and return it as a string
#
# Returns
#	True/False:	Success or failure
#	str:		file contents (success) or exception info(failure)
#=================================================================
def get_file_contents(arg_path):
	try:
		file = open(arg_path, "r")
		text = file.read()
		file.close()
		return (True, text)
	except Exception as e:
		return (False, repr(e))

#=================================================================
# Sign a CSR file for the given user, 
# storing the result in the CRT file
#
# Returns
#	True/False:	Success or failure
#=================================================================
def sign_csr(arg_userid, arg_csr_path, arg_crt_path):
	# csr = User CSR file in internal crypto format
	(result, buffer) = get_file_contents(arg_csr_path)
	if not result:
		app.logger.error("sign_csr: cannot access CSR {%s} for user {%s}, reason: {%s}", arg_csr_path, arg_userid, buffer)
		return False
	try:
		csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, buffer)
	except Exception as e:
		app.logger.error("sign_csr: load CSR {%s} for user {%s} failed, reason: {%s}", arg_csr_path, arg_userid, repr(e))
		return False
	# CAcertificate = CA certificate in internal crypto format
	(result, buffer) = get_file_contents(CA_CRT_FILE)
	if not result:
		app.logger.error("sign_csr: cannot access CA certificate {%s} for user {%s}, reason: {%s}", CA_CRT_FILE, arg_userid, repr(e))
		return False
	try:
		CAcertificate = crypto.load_certificate(crypto.FILETYPE_PEM, buffer)
		if app.debug:
			app.logger.debug("sign_csr: CA cert subject = {%s}", CAcertificate.get_subject())
	except Exception as e:
		app.logger.error("sign_csr: load CA certificate {%s} for user {%s} failed, reason: {%s}", CA_CRT_FILE, arg_userid, repr(e))
		return False
	# CAprivatekey = CA private key in internal crypto format
	(result, buffer) = get_file_contents(CA_KEY_FILE)
	if not result:
		app.logger.error("sign_csr: cannot access CA private key {%s} for user {%s}, reason: {%s}", CA_KEY_FILE, arg_userid, buffer)
		return False
	try:
		CAprivatekey = crypto.load_privatekey(crypto.FILETYPE_PEM, buffer)
	except Exception as e:
		app.logger.error("sign_csr: load CA private key {%s} for user {%s} failed, reason: {%s}", CA_KEY_FILE, arg_userid, repr(e))
	# Sign CSR, giving the CRT
	try:
		cert = crypto.X509()
		cert.set_serial_number(int(uuid.uuid4()))
		cert.gmtime_adj_notBefore(0)
		cert.gmtime_adj_notAfter(EXPIRY_PERIOD)
		cert.set_issuer(CAcertificate.get_subject())
		subject = csr.get_subject() # will log the subject later
		cert.set_subject(subject)
		cert.set_pubkey(csr.get_pubkey())
		cert.sign(CAprivatekey, DIGEST)
	except Exception as e:
		app.logger.error("sign_csr: Cannot sign CSR {%s} for user {%s}, reason: {%s}", arg_csr_path, arg_userid, repr(e)) 
		return False
	# Store signed CRT
	try:
		file = open(arg_crt_path, "w")
		file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
		file.flush()
		os.fsync(file)
		file.close()
	except Exception as e:
		app.logger.error("sign_csr: Cannot store CRT {%s} for user {%s}, reason: {%s}", arg_crt_path, arg_userid, repr(e))
		return False
	# Success
	app.logger.info("sign_csr: Success with CRT {%s} for user {%s}, subject={%s}", arg_csr_path, arg_userid, subject)
	return True

