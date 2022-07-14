#!/bin/bash
MYNAME=`basename $0`
#--------------------------------------------------
rm -rf csrs
if [ $? -ne 0 ]; then
	echo "*** $MYNAME: failed to rm -rf csrs"
fi
mkdir csrs
if [ $? -ne 0 ]; then
	echo "*** $MYNAME: failed to mkdir csrs"
fi
echo " "
echo "================================================================="
echo "$MYNAME: For alice (SSL client), generate private/public keys and generate a CSR"
cd alice
if [ $? -ne 0 ]; then
	echo "*** $MYNAME: failed to cd to alice"
	exit 86
fi
../bin/gen_key_csr.sh
if [ $? -ne 0 ]; then
	exit 86
fi
#--------------------------------------------------
echo " "
echo "================================================================="
echo "$MYNAME: For bob (SSL server), generate private/public keys and generate a CSR"
cd ../bob
if [ $? -ne 0 ]; then
	echo "*** $MYNAME: failed to cd to bob"
	exit 86
fi
../bin/gen_key_csr.sh
if [ $? -ne 0 ]; then
	exit 86
fi
#--------------------------------------------------
echo $MYNAME: End
