MYNAME=`basename $0`

if [ ! -r diyca.version ]; then
	echo "*** $MYNAME: Not positioned in the right place ***"
	exit 86
fi

echo "*******************"
echo "* Cert for Calvin *"
echo "*******************"
openssl x509 -in certs/diyca_calvin.crt -noout -text
echo "***********************"
echo "* Cert for Web Server *"
echo "***********************"
openssl x509 -in certs/diyca_web.crt -noout -text

