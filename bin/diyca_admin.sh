#!/bin/bash
export MYNAME=`basename $0`
#
# Administrative shell script
# Running under the root user
# This start-up file produces entries in the Linux /var/log/syslog* files
# Post start-up, the Python programs use log/diyca.log
#    and echo log entries on stdout (if available)
#
logger -s -t $MYNAME "Begin"
. bin/diyca_common.bash
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** bin/diyca_common.bash is inaccessible"
	exit 86
fi
diyca_validate_tree
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** bin/diyca_common.bash[diyca_validate_tree] failed"
	exit 86
fi
# The empty allow_nonroot file is only for debugging.
# Normally, it is not present.
if [ ! -r allow_nonroot ]; then
	USERID=`id -u $USER`
	if [ $USERID -ne 0 ]; then
		logger -i -t $MYNAME "*** Expected User ID = 0; observed USER=$USER, ID=$USERID"
		exit 86
	fi
fi
cd app_web
if [ $? -ne 0 ]; then
	logger -i -t $MYNAME "*** Failed to cd to app_web"
	exit 86
fi
python diyca_admin.py
if [ $? -ne 0 ]; then
	logger -i -t $MYNAME "*** diyca_admin.py failed"
	exit 86
fi

