
cd bob
if [ $? -ne 0 ]; then
	echo "*** $MYNAME: failed to cd to bob"
	exit 86
fi

echo "Start bob, the SSL server"
python bob.py bob_run.cfg

