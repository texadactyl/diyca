#!/bin/bash
#---------------------------------
# Set up app_web
# Should be positioned at treetop
#---------------------------------
MYNAME=`basename $0`
HERE=`pwd`
CA_CERT_CONFIG=$HERE/bin/diyca_calvin_cert.cfg
CA_CERT_FILE=$HERE/certs/diyca_calvin.crt
CA_KEY_NAME=$HERE/calvin/private/diyca_calvin.key
USER_CERT_CONFIG=$HERE/bin/diyca_web_cert.cfg
USER_OUT_KEY_NAME=$HERE/app_web/private/diyca_web.key
USER_CSR=$HERE/signer/temp_web.csr
USER_OUT_CRT=$HERE/certs/diyca_web.crt
USER_OUT_KEY_SIZE=2048
#-----------------------------------------------------------
echo $MYNAME{app_web}: Generate Public/Private Key $USER_OUT_KEY_NAME
openssl genrsa -out $USER_OUT_KEY_NAME $USER_OUT_KEY_SIZE
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed: openssl genrsa -out $USER_OUT_KEY_NAME $USER_OUT_KEY_SIZE"
	exit 86
fi
#-----------------------------------------------------------
echo $MYNAME{app_web}: Generate Certificate Signing Request $USER_CSR
openssl req -new -config $USER_CERT_CONFIG -key $USER_OUT_KEY_NAME -out $USER_CSR
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed: openssl req -new -config $CA_CERT_CONFIG -key $USER_OUT_KEY_NAME -out $USER_CSR"
	exit 86
fi
#-----------------------------------------------------------
echo $MYNAME{calvin}: Sign the CSR for app_web, creating a CRT
cd calvin
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to cd to calvin"
	exit 86
fi
openssl ca -batch \
	-cert $CA_CERT_FILE \
    -config $CA_CERT_CONFIG \
	-keyfile $CA_KEY_NAME \
    -in $USER_CSR \
    -out $USER_OUT_CRT
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to sign the USER_CSR"
	exit 86
fi
cd $HERE
if [ $? -ne 0 ]; then
	logger -s -t $MYNAME "*** failed to cd to parent directory"
	exit 86
fi
rm -f $USER_CSR
#-----------------------------------------------------------
echo $MYNAME: End
