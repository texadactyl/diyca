MYNAME=`basename $0`

if [ ! -r diyca.version ]; then
	echo "*** $MYNAME: Not positioned in the right place ***"
	exit 86
fi

echo "************"
echo "* Users    *"
echo "************"
sqlite3 -line app_web/diyca_web.db 'select * from tuser;'

