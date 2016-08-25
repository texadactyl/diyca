MYNAME=`basename $0`
DIRNAME=`pwd`
CONFIG=$DIRNAME/gen_key_csr.cfg
if [ ! -r $CONFIG ]; then
	echo "*** $MYNAME: $CONFIG is not accessible ***"
	exit 86
fi
. $CONFIG
echo " "
echo $MYNAME: Generate the public-private key pair
openssl genrsa -out $OUTKEYNAME $OUTKEYSIZE
if [ $? -ne 0 ]; then
	exit 86
fi
echo " "
echo $MYNAME: Generate a CSR
openssl req -new -config $CERTCONFIG -key $OUTKEYNAME -out $OUTCSR
if [ $? -ne 0 ]; then
	exit 86
fi
echo $MYNAME: End
