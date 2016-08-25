#!/bin/bash
MYNAME=`basename $0`
#
# Launched by /etc/rc.local
# Running under the root user
# This start-up file produces entries in the Linux /var/log/syslog* files
# Post start-up, the Python programs use log/diyca.log
#    and echo log entries on stdout (if available)
#
logger -i -t $MYNAME "Begin"
# The empty allow_nonroot file is only for debugging.
# Normally, it is not present.
if [ ! -r allow_nonroot ]; then
	USERID=`id -u $USER`
	if [ $USERID -ne 0 ]; then
		logger -i -t $MYNAME "*** Expected User ID = 0; observed USER=$USER, ID=$USERID"
		exit 86
	fi
fi
#---------------------------------
(cd app_web; python diyca_web_main.py) &
#---------------------------------
logger -i -t $MYNAME "End - web server launched"
