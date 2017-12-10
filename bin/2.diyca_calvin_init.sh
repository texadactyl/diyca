#!/bin/bash
#---------------------------------
# Set up CA, "calvin"
# Should be positioned at treetop
#---------------------------------
export MYNAME=`basename $0`
HERE=`pwd`
CERTCONFIG=$HERE/bin/diyca_calvin_cert.cfg
OUTKEYNAME=$HERE/calvin/private/diyca_calvin.key
OUTCSR=$HERE/calvin/temp_calvin.csr
OUTCRT=$HERE/certs/diyca_calvin.crt
#---------------------------------
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
logger -s -t $MYNAME "Make calvin, a self-signed CA, ready for business"
cd calvin
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to cd to calvin"
	exit 86
fi
#---------------------------------
logger -s -t $MYNAME Initialize subdirectories
rm -rf certs db private
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to rm -rf certs db private"
	exit 86
fi
mkdir certs db private
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to mkdir certs db private"
	exit 86
fi
touch db/index
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to touch db/index"
	exit 86
fi
touch db/index.attr
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to touch db/index.attr"
	exit 86
fi
openssl rand -hex 16  > db/serial
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to openssl rand -hex 16 to db/serial"
	exit 86
fi
logger -s -t $MYNAME 1001 > db/crlnumber
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to logger -s -t $MYNAME 1001 to db/crlnumber"
	exit 86
fi
#---------------------------------
logger -s -t $MYNAME Generate the public-private key pair and my CSR
openssl req -new -nodes \
    -config $CERTCONFIG \
    -out $OUTCSR \
    -keyout $OUTKEYNAME
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to generate the public-private key pair or CSR"
	exit 86
fi
#---------------------------------
logger -s -t $MYNAME Generate a CSR and a self-signed CRT for calvin
openssl ca -batch -selfsign \
    -config $CERTCONFIG \
	-keyfile $OUTKEYNAME \
    -in $OUTCSR \
    -out $OUTCRT
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to generate the CSR and self-signed CRT"
	exit 86
fi
cd ..
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to cd to parent directory"
	exit 86
fi
#---------------------------------
logger -s -t $MYNAME End
