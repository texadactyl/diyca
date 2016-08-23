#!/bin/bash
#------------------------------------
# Put tree into a known state (clean)
# Should be positioned at treetop
#------------------------------------
export MYNAME=`basename $0`
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
#---------------------------------
logger -s -t $MYNAME "Remove all CRT files"
find . -name '*.crt' -exec rm {} \;
logger -s -t $MYNAME "Remove all CSR files"
find . -name '*.csr' -exec rm {} \;
logger -s -t $MYNAME "Remove all KEY files"
find . -name '*.key' -exec rm {} \;
logger -s -t $MYNAME "Remove all PYC files"
find . -name '*.pyc' -exec rm {} \;
logger -s -t $MYNAME "Remove all DB files"
find . -name '*.db' -exec rm {} \;
logger -s -t $MYNAME "Re-create app_web/private subdirectory"
rm -rf app_web/private; mkdir app_web/private
logger -s -t $MYNAME "Re-create the calvin subdirectory"
rm -rf calvin; mkdir calvin
logger -s -t $MYNAME "Re-create the signer subdirectory"
rm -rf signer; mkdir signer
logger -s -t $MYNAME "Re-create the certs subdirectory"
rm -rf certs; mkdir certs
logger -s -t $MYNAME "Re-create the log subdirectory"
rm -rf log; mkdir log
#---------------------------------
logger -s -t $MYNAME "End"
