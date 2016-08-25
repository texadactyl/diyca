"""
DIYCA - Main Web Program
"""

# Python imports
import sys, os, signal, socket, shutil
import logging
from logging.handlers import TimedRotatingFileHandler

# 3rd party imports
from werkzeug.utils import secure_filename
from flask import Flask, session, request, render_template
from flask import make_response, send_file

# Web Server app imports
import diyca_web_utilities as util
import diyca_web_signer as signer

# Initialize constants
MYNAME = "diyca_web_main"
MAX_TCP_PORT = 65535
MIN_TCP_PORT = 1
SESSION_COOKIE_NAME = "dummy"
SESSION_USERID = "userid"
SESSION_EMAIL = "email"
CFGFILE = "diyca_web.cfg"
SIGNER_FOLDER = "dummy"
ALLOWED_EXTENSIONS = set(["csr"])
UNAME = os.uname()

# Initialize Flask
app = Flask(MYNAME,
				template_folder="templates",
				static_folder="static")

#------------ Internal procedures ------------------------------------

# Catch termination signals
def signal_handler(arg_signal, arg_frame):
	app.logger.warn("signal_handler: Caught signal {%d}", arg_signal)
	util.dbclose()
	func = request.environ.get('werkzeug.server.shutdown')
	if func is None:
		app.log.error("signal_handler: FAILED: request.environ.get('werkzeug.server.shutdown')")
		app.logger.warn("signal_handler: Executing a sys.exit(0) instead")
		sys.exit(0)
	app.logger.warn("signal_handler: Doing a 'werkzeug.server.shutdown'")
	func()

# Uploaded file: allowed file extension (type)?
def allowed_file(filename):
	if '.' not in filename:
		return False
	return (filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS)

# Create a web response from a rendered page that ensures no caching
def ensure_no_caching(arg_rendered):
	response = make_response(arg_rendered)
	response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
	response.headers["Pragma"] = "no-cache"
	response.headers["Expires"] = "0"
	return response

# Render a main_form from userid, email address, and status text
def main_form_renderer(arg_userid, arg_email, arg_status_text):
	out_rendered = render_template("menu_form.html",
									frm_uname = UNAME,
									frm_userid = arg_userid,
									frm_email = arg_email,
									frm_status = arg_status_text)
	return out_rendered

# Build a response which will end the session and expire the session cookie
def build_logout_response(arg_html_text):
	out_response = make_response(arg_html_text)
	out_response.set_cookie(SESSION_COOKIE_NAME, "", expires=0)
	session.clear()
	return out_response

#------------ Web Server Entry Points --------------------------------

# Main entry point (/)
# if in session, stay in session --> main_form
# Else, present login form
@app.route("/", methods=["GET"])
def web_request_initial_contact():
	if SESSION_USERID in session:
		userid = session[SESSION_USERID]
		email = session[SESSION_EMAIL]
		if app.debug:
			app.logger.debug("web_request_initial_contact: Already in session with user {%s}", userid)
		hello = util.sprintf("Hello, %s", userid)
		rendered = main_form_renderer(userid, email, hello)
		return ensure_no_caching(rendered), 200
	# Not currently in session
	if app.debug:
		app.logger.debug("web_request_initial_contact: Not currently in session")
	rendered = render_template("login_form.html",
									frm_uname = UNAME,
									frm_userid = "",
									frm_password = "",
									frm_status = "")
	return ensure_no_caching(rendered), 200

# Process a web login form (userid, password)
@app.route("/login", methods=["POST"])
def web_request_login():
	userid = request.form["userid"]
	if app.debug:
		app.logger.debug("web_request_login: userid is {%s}", userid)
	# Hash the password
	password = util.hash_a_secret(request.form["password"])
    # Get database row for this userid
	row = util.dbuser_get(userid)
	if row is None:
		# User not found
		app.logger.error("web_request_login: user {%s} NOT FOUND", userid)
		rendered = render_template("login_form.html", 
									frm_uname = UNAME,
									frm_userid = userid,
									frm_password = "",
									frm_status = "* NO SUCH USER ID *")
		return ensure_no_caching(rendered), 200
	# Extract row columns for userid
	(dummy, email, db_password, stamp) = row
	# Valid password entered?
	if password != db_password:
		#Invalid password
		app.logger.error("web_request_login: user {%s} provided an INVALID PASSWORD", userid)
		rendered = render_template("login_form.html", 
									frm_uname = UNAME,
									frm_userid = userid,
									frm_password = email,
									frm_status = "* INVALID PASSWORD *")
		return ensure_no_caching(rendered), 200
	# Password valid
	session[SESSION_USERID] = userid
	session[SESSION_EMAIL] = email
	hello = util.sprintf("Hello, %s", userid)
	rendered = main_form_renderer(userid, email, hello)
	app.logger.info("web_request_login: user {%s} successfully logged in", userid)
	return ensure_no_caching(rendered), 200

# Process a web /gotoregister request from the Login form
@app.route("/gotoregister", methods=["GET"])
def web_request_goto_register():
		rendered = render_template("register_form.html", 
									frm_uname = UNAME,
									frm_userid = "",
									frm_email = "",
									frm_password1 = "",
									frm_password2 = "",
									frm_status = "")
		return ensure_no_caching(rendered), 200

# Process a web register form
@app.route("/register", methods=["POST"])
def web_request_register():
	userid = request.form["userid"]
	email = request.form["email"]
	# Validate email address
	if not util.verify_email_recipient(email):
		rendered = render_template("register_form.html", 
									frm_uname = UNAME,
									frm_userid = userid,
									frm_email = email,
									frm_password1 = "",
									frm_password2 = "",
									frm_status = "* INVALID EMAIL ADDRESS *")
		app.logger.error("web_request_register: userid {%s / %s} provided an INVALID EMAIL ADDRESS", userid, email)
		return ensure_no_caching(rendered), 200
	# Hash the first password field (Javascript in the register_form ensured that they are equal)
	ok_password = util.hash_a_secret(request.form["password1"])
	# Add user to database
	if util.dbuser_add(userid, ok_password, email):
		# Success
		session[SESSION_USERID] = userid
		session[SESSION_EMAIL] = email
		hello = util.sprintf("Hello, %s", userid)
		rendered = main_form_renderer(userid, email, hello)
		app.logger.info("web_request_register: userid {%s / %s} successfully registered", userid, email)
		return ensure_no_caching(rendered), 200
	# Failed, user already exists
	app.logger.error("web_request_register: user {%s} already exists", userid)
	rendered = render_template("register_form.html",
								frm_uname = UNAME,
								frm_userid = userid,
								frm_email = email,
								frm_password1 = "",
								frm_password2 = "",
								frm_status = "* USER ALREADY EXISTS *")
	return ensure_no_caching(rendered), 200

@app.route("/selected", methods=["POST"])
def web_request_selected():
	if SESSION_USERID in session:
		userid = session[SESSION_USERID]
		email = session[SESSION_EMAIL]
	else:
		# No current session - impossible!
		text = "web_request_selected: No current session; logged out"
		app.logger.error(text)
		response = build_logout_response("<h3>*** " + text + "</h3>")
		return response, 400
	function = request.form["function"]
	if app.debug:
		app.logger.debug("web_request_selected: form with function {%s} received", function)
	if function == "csr":
		rendered = render_template("csr_form.html",
								frm_uname = UNAME,
								frm_userid = userid, 
								frm_email = email,
								frm_status = "")
		return ensure_no_caching(rendered)
	elif function == "chgpswd":
		rendered = render_template("chgpswd_form.html",
								frm_uname = UNAME,
								frm_userid = userid, 
								frm_email = email,
								frm_status = "")
		return ensure_no_caching(rendered)
	elif function == "logout":
		text = util.sprintf("User {%s} logged out", userid)
		rendered = render_template("login_form.html", 
									frm_uname = UNAME,
									frm_userid = "",
									frm_password = "",
									frm_status = text)
		app.logger.info("web_request_selected: " + text)
		response = ensure_no_caching(rendered)
		response.set_cookie(SESSION_COOKIE_NAME, "", expires=0)
		session.clear()
		return response, 200
	# Unrecognizable function - impossible!
	text = util.sprintf("web_request_selected: *** function {%s} is unsupported; logged out ***", function)
	app.logger.error(text)
	response = build_logout_response("<h3>*** " + text + "</h3>")
	return response, 400

@app.route("/change_password", methods=["POST"])
def web_request_change_password():
	if SESSION_USERID in session:
		userid = session[SESSION_USERID]
		email = session[SESSION_EMAIL]
	else:
		# Not in session - impossible!
		text = "web_request_change_password(): No current session; logged out"
		app.logger.error(text)
		response = build_logout_response("<h3>*** " + text + "</h3>")
		return response, 400
	# Hash the current password
	password = util.hash_a_secret(request.form["password"])
    # Get database row for this userid
	row = util.dbuser_get(userid)
	if row == None:
		# User not found - impossible!
		text = util.sprintf("web_request_change_password: user {%s} NOT FOUND; logged out", userid)
		app.logger.error(text)
		response = build_logout_response("<h3>*** " + text + "</h3>")
		return "<h3>"+text+"</h3>", 400
	# Extract row columns for userid
	(dummy, email, db_password, stamp) = row
	# Valid password entered?
	if password != db_password:
		#Invalid password
		app.logger.error("web_request_change_password: user {%s} provided an INVALID PASSWORD", userid)
		rendered = render_template("chgpswd_form.html", 
									frm_uname = UNAME,
									frm_userid = userid,
									frm_password = email,
									frm_status = "* INVALID PASSWORD *")
		return ensure_no_caching(rendered), 200
	# Hash the new password field
	ok_password = util.hash_a_secret(request.form["password1"])
	# Update user with new password
	if util.dbuser_update_password(userid, ok_password):
		# Success
		rendered = main_form_renderer(userid, email, "Password changed")
		app.logger.info("web_request_change_password: userid {%s / %s} successfully changed password", userid, email)
		return ensure_no_caching(rendered), 200
	# Report database update error
	app.logger.error("web_request_change_password: Could not update password for user {%s}", userid)
	rendered = main_form_renderer(userid, email, "*** Password change FAILED ***")
	return ensure_no_caching(rendered), 204

# Sign an uploaded CSR file, yielding a CRT file
@app.route("/signcsr", methods=["POST"])
def web_request_sign_csr():
	userid = session[SESSION_USERID]
	email = session[SESSION_EMAIL]
	# Check for the impossible
	if "file" not in request.files:
		text = util.sprintf("web_request_sign_csr from user {%s}: 'file' missing from request.files", userid)
		app.logger.error(text)
		return text, 400
	csr_file_obj = request.files["file"]
	if csr_file_obj.filename == "":
		text = util.sprintf("web_request_sign_csr from user {%s}: csr_file_obj.filename is empty", userid)
		app.logger.error(text)
		return text, 400
	if not allowed_file(csr_file_obj.filename):
		app.logger.error("web_request_sign_csr from user {%s}: csr_file_obj.filename {%s} is not an allowed type", userid, csr_file_obj.filename)
		wstr = util.sprintf("*** File extension of {%s} is invalid. Only 'csr' extensions are permitted. ***", csr_file_obj.filename)
		rendered = render_template("csr_form.html",
								frm_uname = UNAME,
								frm_userid = userid, 
								frm_email = email,
								frm_status = wstr)
		return ensure_no_caching(rendered), 200
	# Save it
	csr_filename = secure_filename(csr_file_obj.filename)
	csr_filepath = os.path.join(SIGNER_FOLDER, csr_filename)
	csr_file_obj.save(csr_filepath)
	app.logger.info("File {%s} successfully uploaded for user {%s}", csr_filepath, userid)
	# Sign file
	crt_filename = csr_filename.rsplit(".", 1)[0] + ".crt"
	crt_filepath = os.path.join(SIGNER_FOLDER, crt_filename)
	if not signer.sign_csr(userid, csr_filepath, crt_filepath):
		app.logger.error("web_request_sign_csr {%s} from user {%s}: invalid contents (CA sign failed)", csr_file_obj.filename, userid)
		text = util.sprintf("*** Invalid CSR File Contents (%s) ***", csr_filename)
		rendered = render_template("csr_form.html",
								frm_uname = UNAME,
								frm_userid = userid, 
								frm_email = email,
								frm_status = text)
		return ensure_no_caching(rendered), 200
	if app.debug:
		app.logger.debug("web_request_sign_csr CRT {%s} from user {%s}: CA sign successful", crt_filename, userid)
	# Successful: CRT = signed(CSR)
	# Remove the uploaded CSR file
	try:
		os.remove(csr_filepath)
	except Exception as e:
		app.logger.error("Failed to remove CSR {%s} for user {%s}, reason: {%s}", csr_filepath, userid, repr(e))
		# Do not alarm the user
	# Download CRT file to user
	return send_file(crt_filepath, 
						mimetype='application/pkix-cert',
						attachment_filename=crt_filename,
						as_attachment=True)

#------------ Begin Launched Program ------------------------------------

if __name__ == "__main__":
	nargs = len(sys.argv)
	# Ensure that there are no arguments after python program name
	if nargs != 1:
		text = util.sprintf("%s: Command line error, nargs=%s, should be 1", __name__, nargs)
		print(text)
		sys.exit(86)
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
	# Get and process the remaining configuration parameters
	app.logger.info("============================== WEB SERVER INITIALISATION ======================")
	app.logger.info("Configuration file = %s", CFGFILE)
	# Get and process Web Server SSL key file parameter
	ssl_key_file = app.config["SSL_KEY_FILE"]
	app.logger.info("SSL_KEY_FILE = %s", ssl_key_file)
	if not os.path.isfile(ssl_key_file):
		with app.app_context():
			util.oops("SSL key file {%s} inaccessible", ssl_key_file)
	# Get and process Web Server SSL certificate file parameter
	ssl_crt_file = app.config["SSL_CRT_FILE"]
	app.logger.info("SSL_CRT_FILE = %s", ssl_crt_file)
	if not os.path.isfile(ssl_crt_file):
		with app.app_context():
			util.oops("SSL CRT file {%s} inaccessible", ssl_crt_file)
	# Open database
	dbpath = app.config["DBPATH"]
	app.logger.info("DBPATH = %s", dbpath)
	with app.app_context():
		util.dbopen(dbpath)
	# Establish session parameters
	app.config["SECRET_KEY"] = os.urandom(24)
	app.logger.info("PERMANENT_SESSION_LIFETIME = %d", 
					app.config["PERMANENT_SESSION_LIFETIME"])
	SESSION_COOKIE_NAME = app.config["SESSION_COOKIE_NAME"]
	app.logger.info("SESSION_COOKIE_NAME = %s", str(app.config["SESSION_COOKIE_NAME"]))
	# Get the remaining configuration parameters
	app.logger.info("DEBUG = %s", str(app.config["DEBUG"]))
	str_port = app.config["PORT"]
	app.logger.info("PORT = %s", str_port)
	pid_path = app.config["PID_PATH"]
	app.logger.info("PID_PATH = %s", pid_path)
	# Validate TCP port number as numeric anplutod in range
	tcp_port = -1
	try:
		tcp_port = int(str_port)
	except Exception as e:
		with app.app_context():
			util.oops("tcp_port = int(%s) failed (not an integer)", str_port)
	if tcp_port > MAX_TCP_PORT:
		with app.app_context():
			util.oops("tcp_port (%d) exceeds the maximum port number permitted (%d)", 
						tcp_port, MAX_TCP_PORT)
	if tcp_port < MIN_TCP_PORT:
		with app.app_context():
			util.oops("tcp_port (%d) is smaller than the minimum port number permitted (%d)", 
						tcp_port, MIN_TCP_PORT)
	# Initialize temp folder for CSR & CRT files
	SIGNER_FOLDER = app.config["SIGNER_FOLDER"]
	shutil.rmtree(SIGNER_FOLDER)
	os.mkdir(SIGNER_FOLDER)
	# Save process ID in a file which can be read by an admin user
	file = open(pid_path, "w")
	pid = os.getpid()
	app.logger.info("O/S PID = %d", pid)
	file.write(str(pid))
	file.flush()
	os.fsync(file)
	file.close()
	
	# Proceed; listen for HTTP requests on tcp_port
	app.logger.info("============================== WEB SERVER BEGINS ==============================")
	try:
		context = (ssl_crt_file, ssl_key_file)
		app.run(host="0.0.0.0",
						port=tcp_port, 
						ssl_context=context, 
						threaded=False, 
						use_reloader=False)
	except socket.error, (value,message):
		with app.app_context():
			util.oops("Socket error (%d,%s) trying to bind tcp_port (%d)",
						value, message, tcp_port)
