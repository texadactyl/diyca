
import diyca_web_signer as signer
from flask import Flask
import logging
from logging.handlers import TimedRotatingFileHandler

CSR = "/home/elkins/test.csr"
CRT = "/home/elkins/test.crt"
CFGFILE="diyca_web.cfg"

app = Flask(__name__.split('.')[0])
app.config.from_pyfile(CFGFILE)
logfile = app.config["LOGFILE"]
logformat = app.config["LOGFORMAT"]
handler = TimedRotatingFileHandler(logfile, 
									when='midnight', 
									interval=1,
									backupCount=10)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(logformat)
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

with app.app_context():
	signer.sign_csr("mickey", CSR, CRT)
