"""
DIYCA - Admin Program
"""

# Python imports
import sys, os, signal
import logging
from logging.handlers import TimedRotatingFileHandler

# 3rd party imports
from flask import Flask

# Web Server app imports
import diyca_web_utilities as util

# Initialize constants
MYNAME = "diyca_admin"
CFGFILE = "diyca_web.cfg"
RESET_PASSWORD = "123456"

# Initialize Flask
app = Flask(MYNAME)

#------------ Internal procedures ------------------------------------

# Immediately shutdown this web server after closing the database
def byebye():
	sys.exit(0)

# Catch termination signals
def signal_handler(arg_signal, arg_frame):
	app.logger.info("signal_handler: Caught signal {%d}, exiting", arg_signal)
	byebye()

# Prompt for a response
def prompt(arg_prompt_message):
	return raw_input(arg_prompt_message)

# Killer process based on web server's PID file contents: send a SIGTERM signal
def killer():
	try:
		# Read PID file
		pid_path = app.config["PID_PATH"]
		file = open(pid_path, "r")
		str_pid = file.read()
		# Set pid to numeric version of PID file contents
		pid = -1
		try:
			pid = int(str_pid)
		except:
			with app.app_context():
				app.logger.error("PID string (%s) is not an integer", str_pid)
			return
		# Signal the web server to exit
		print
		os.kill(pid, signal.SIGTERM)
		# Remove the PID file
		os.remove(pid_path)
		app.logger.info("killer: Process {%d} terminated", pid)
	except Exception as err:
		app.logger.error("killer: Cannot kill web server, reason: {%s}", repr(err))

# Get a user ID from the operator
def get_user_id():
	userid = prompt("get_user_id: Enter the user ID or a nil string to cancel: ")
	if userid == "":
		print("get_user_id: Cancelled")
		return ""
	return userid

# Reset a user's password to RESET_PASSWORD
def reset_password():
	userid = get_user_id()
	if userid == "":
		return
	text = util.sprintf("reset_password: Are you REALLY REALLY REALLY sure that you want to reset the password of user {%s}? (y/Y=yes; anything else=no): ", userid)
	yesorno = prompt(text)
	if yesorno == "Y" or yesorno == "y":
		with app.app_context():
			# Open database
			dbpath = app.config["DBPATH"]
			util.dbopen(dbpath)
			# Reset password
			hashed_password = util.hash_a_secret(RESET_PASSWORD)
			# Update the user's password
			if util.dbuser_update_password(userid, hashed_password):
				app.logger.info("reset_password: User {%s} password set to {%s}", userid, RESET_PASSWORD)
			# Close database
			util.dbclose()
	else:
		print("reset_password: Cancelled")

# Delete a user
def delete_user():
	userid = get_user_id()
	if userid == "":
		return
	text = util.sprintf("delete_user: Are you REALLY REALLY REALLY sure that you want to delete user {%s}? (y/Y=yes; anything else=no): ", userid)
	yesorno = prompt(text)
	if yesorno == "Y" or yesorno == "y":
		with app.app_context():
			# Open database
			dbpath = app.config["DBPATH"]
			util.dbopen(dbpath)
			# User exists?
			row = util.dbuser_get(userid)
			if row is None:
				app.logger.error("delete_user: User {%s} does not exist", userid)
				util.dbclose()
				return
			# Remove user
			if util.dbuser_remove(userid):
				app.logger.info("delete_user: User {%s} deleted", userid)
			# Close database
			util.dbclose()
	else:
		print("delete_user: Cancelled")

#------------ Begin Launched Program ------------------------------------

if __name__ == "__main__":
	nargs = len(sys.argv)
	# Ensure that there are no arguments after python program name
	if nargs != 1:
		text = util.sprintf("Command line error, nargs=%s, should be 1", nargs)
		print(text)
		sys.exit(86)
	# Catch termination signals
	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	# Connect to application configuration
	app.config.from_pyfile(CFGFILE)
	# Initialize logging
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
	# Get the remaining configuration parameters
	app.logger.info("DEBUG = %s", str(app.config["DEBUG"]))

	# Proceed; listen for HTTP requests on tcp_port
	app.logger.info("============================== ADMIN BEGINS ==============================")

	while True:
		print
		print("* Admin Menu *")
		print("* ========== *")
		print("* ")
		print("* 1 - Shut down web server")
		text = util.sprintf("* 2 - Set user password to %s", RESET_PASSWORD)
		print(text)
		print("* 3 - Delete user")
		print("* x/X - Exit")
		print("* ")
		answer = prompt("* Selection: ")
		print

		if answer == "1":
			killer()
		elif answer == "2":
			reset_password()
		elif answer == "3":
			delete_user()
		elif answer == "x" or answer == "X":
			app.logger.info("============================== ADMIN ENDED ==============================")
			byebye()
		elif answer == "":
			dummy = 1
		else:
			print("*** Invalid selection ***")
			


		
		


