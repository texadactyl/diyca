"""
DIYCA - DDL for the database
"""

# Tables
TBL_USER = "tuser"				# registered user table

# All timestamps are formatted as a string: YYYY-MM-DD_hh:mm:ss (19 bytes)
# See diyca_web_utilities.py variable, FORMAT_DB_TIMESTAMP.

# Fields of table TBL_USER
FLD_USER_ID = "fuserid"			# user ID [primary key]
FLD_USER_EMAIL = "fuseremail"	# email address
FLD_USER_PSWD = "fuserpswd"		# hashed password
FLD_USER_TSTAMP = "fuserstamp"	# timestamp of TBL_USER record insertion [non-unique key]
