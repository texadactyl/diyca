"""
diyca - Utilities for the Main Web Program
"""

import sys
import os
import time
import hashlib
import base64
import errno
import re
import sqlite3
import dns.resolver

from flask import current_app as app
import diyca_web_ddl as ddl

#==========
# Constants
#==========
FORMAT_DB_TIMESTAMP = "%Y-%m-%d_%H:%M:%S"

#====================================
# Database connection global variable
#====================================
dbconn = None

def oops(arg_format, *arg_list):
    """
    Log and abort
    """
    total_format = "*** Oops, " + arg_format
    buffer = total_format %arg_list
    app.logger.error(buffer)
    app.logger.info("Closing DB if open and then exiting to the OS")
    dbclose()
    sys.exit(86)

def hash_a_secret(arg_secret):
    """
    Secure-hash a secret
    """
    hashish = hashlib.sha512(arg_secret.encode('utf-8'))
    return base64.b64encode(hashish.digest()).decode('utf-8')

def sprintf(arg_format, *arg_list):
    """
    Sprintf, C-language style
    """
    buffer = arg_format %arg_list
    return buffer

def verify_email_recipient(arg_recipient):
    """
    Verify an email recipient - syntax and query DNS for domain status
    Did not use SMTP to verify account because server behavior is unpredictable
    """
    if app.debug:
        app.logger.debug("verify_email_recipient: email recipient = %s",
                         arg_recipient)
    # Inspect email address
    result = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$',
                      arg_recipient)
    if result is None:
        if app.debug:
            app.logger.debug("verify_email_recipient: Not an email address: %s",
                             arg_recipient)
        return False
    # Extract domain name from arg_recipient
    pieces = arg_recipient.split("@")
    if len(pieces) != 2:
        if app.debug:
            app.logger.debug("verify_email_recipient: Did not split into 2 pieces: %s",
                             arg_recipient)
        return False
    domain = pieces[1]
    if app.debug:
        app.logger.debug("verify_email_recipient: email domain = %s",
                         domain)
    # Get MX record for target domain
    try:
        records = dns.resolver.query(domain, 'MX')
        mx_record = str(records[0].exchange)
    except:
        if app.debug:
            app.logger.debug("verify_email_recipient: DNS MX-query exception with %s",
                             domain)
        return False
    if app.debug:
        app.logger.debug("verify_email_recipient: DNS MX record = %s", mx_record)
    return True

def epoch2dbfmt(arg_epoch_time):
    """
    Convert epoch time to database format
    """
    return time.strftime(FORMAT_DB_TIMESTAMP, time.localtime(arg_epoch_time))

def dbfmt2epoch(arg_dbfmt_time):
    """
    Convert database format time to epoch time
    """
    return time.mktime(time.strptime(arg_dbfmt_time, FORMAT_DB_TIMESTAMP))

def dbuser_get(arg_userid):
    """
    Retrieve a user row
    """
    global dbconn
    try:
        dbcursor = dbconn.cursor()
        dbcursor.execute("SELECT * FROM {tn} WHERE {cn1}='{cv1}'" \
                         .format(tn=ddl.TBL_USER, cn1=ddl.FLD_USER_ID, cv1=arg_userid))
        row = dbcursor.fetchone()
        if row is None:
            return None
        return row
    except sqlite3.Error as exc:
        app.logger.error("dbuser_update_ts: SELECT {%s} failed, reason: {%s}",
                         arg_userid, repr(exc))
        return None

def dbuser_update_password(arg_userid, arg_password):
    """
    Update the password in a given user row
    """
    global dbconn
    try:
        dbcursor = dbconn.cursor()
        dbcursor.execute("UPDATE {tn} SET {cn2}='{cv2}' WHERE {cn1}='{cv1}'" \
                         .format(tn=ddl.TBL_USER, cn1=ddl.FLD_USER_ID,
                                 cv1=arg_userid, cn2=ddl.FLD_USER_PSWD,
                                 cv2=arg_password))
        dbconn.commit()
        return True
    except sqlite3.Error as exc:
        app.logger.error("dbuser_update_ts: UPDATE {%s,%s} failed, reason: {%s}",
                         arg_userid, arg_password, repr(exc))
        return False

def dbuser_add(arg_userid, arg_password, arg_email):
    """
     Add a user record
    """
    global dbconn
    if app.debug:
        app.logger.debug("dbuser_add: arg_userid=%s, arg_email=%s",
                         arg_userid, arg_email)
    try:
        dbcursor = dbconn.cursor()
        stamp = epoch2dbfmt(time.time())
        sql = "INSERT INTO {tn} ('{cn1}', '{cn2}','{cn3}','{cn4}') VALUES ('{cv1}','{cv2}','{cv3}','{cv4}')"\
                .format(tn=ddl.TBL_USER, cn1=ddl.FLD_USER_ID, cv1=arg_userid,
                        cn2=ddl.FLD_USER_PSWD, cv2=arg_password, cn3=ddl.FLD_USER_EMAIL,
                        cv3=arg_email, cn4=ddl.FLD_USER_TSTAMP, cv4=stamp)
        dbcursor.execute(sql)
        dbconn.commit()
    except sqlite3.Error as exc:
        app.logger.error("dbuser_add: INSERT {%s,%s} failed, reason: {%s}",
                         arg_userid, arg_email, repr(exc))
        return False
    # Success
    return True

def dbuser_remove(arg_userid):
    """
    Remove a user record
    """
    global dbconn
    if app.debug:
        app.logger.debug("dbuser_remove: arg_userid=%s", arg_userid)
    try:
        dbcursor = dbconn.cursor()
        dbcursor.execute("DELETE FROM {tn} WHERE {cn1}='{cv1}'" \
                         .format(tn=ddl.TBL_USER, \
                                 cn1=ddl.FLD_USER_ID, cv1=arg_userid))
        dbconn.commit()
    except sqlite3.Error as exc:
        app.logger.error("dbuser_remove: DELETE {%s} failed, reason: {%s}",
                         arg_userid, repr(exc))
        return False
    # Success
    return True

def dbinit():
    """
    Initialize the database
    """
    global dbconn
    try:
        dbcursor = dbconn.cursor()
        # Delete old database tables
        dbcursor.execute("DROP TABLE IF EXISTS {tn}".format(tn=ddl.TBL_USER))
        # Create the user table
        dbcursor.execute("CREATE TABLE {tn} ({cn} {ct} PRIMARY KEY)" \
                         .format(tn=ddl.TBL_USER, cn=ddl.FLD_USER_ID, ct="TEXT"))
        dbcursor.execute("ALTER TABLE {tn} ADD COLUMN '{cn}' {ct}" \
                         .format(tn=ddl.TBL_USER, cn=ddl.FLD_USER_EMAIL, ct="TEXT"))
        dbcursor.execute("ALTER TABLE {tn} ADD COLUMN '{cn}' {ct}" \
                         .format(tn=ddl.TBL_USER, cn=ddl.FLD_USER_PSWD, ct="TEXT"))
        dbcursor.execute("ALTER TABLE {tn} ADD COLUMN '{cn}' {ct}" \
                         .format(tn=ddl.TBL_USER, cn=ddl.FLD_USER_TSTAMP, ct="TEXT"))
    except sqlite3.Error as exc:
        oops("dbinit failed, reason: {%s}", exc.args[0])

def dbopen(arg_dbpath):
    """
    Open database
    """
    global dbconn
    flag_init = False
    # If the database flat file does not yet exist,
    # then create it and close it
    # If just created, set a reminder (flag_init) to initialize it later
    try:
        if not os.path.isfile(arg_dbpath):
            try:
                open(arg_dbpath, "wb").close()
            except IOError as exc:
                if exc.errno == errno.EACCES:
                    oops("dbopen: Access violation while trying to create file {%s}",
                         arg_dbpath)
                oops("dbopen: Error {%s [%d]} occured while trying to create file {%s}",
                     os.strerror(exc.errno), exc.errno, arg_dbpath)
            app.logger.info("dbopen: Created file {%s}", arg_dbpath)
            flag_init = True #reminder for later
    except EnvironmentError as exc:
        oops("dbopen: Touch operation {%s} failed, reason: {%s}",
             arg_dbpath, repr(exc))
    # Ensure that the flat file is readable and close it
    try:
        open(arg_dbpath, 'rb').close()
    except EnvironmentError as exc:
        oops("dbopen: File %s exists but cannot open it, reason: {%s}",
             arg_dbpath, repr(exc))
    # Connect to database
    try:
        dbconn = sqlite3.connect(arg_dbpath)
    except sqlite3.Error as exc:
        oops("dbopen: sqlite3.connect{%s} failed, reason: {%s}", arg_dbpath, repr(exc))
    # If just created, initialize the database
    if flag_init:
        dbinit()
        app.logger.info("dbopen: Initialized database")
    # Success
    app.logger.info("dbopen: Connected to database %s", arg_dbpath)

def dbclose():
    """
    Close database
    """
    global dbconn
    if dbconn is None:
        return
    try:
        dbconn.commit()
        dbconn.close()
        app.logger.info("dbclose: Closed database")
    except EnvironmentError as exc:
        app.logger.error("dbclose: Database failed to commit or close, reason: {%s}",
                         repr(exc))
        return
