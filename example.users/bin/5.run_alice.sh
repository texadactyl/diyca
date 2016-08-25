
cd alice
if [ $? -ne 0 ]; then
	echo "*** $MYNAME: failed to cd to alice"
	exit 86
fi

echo "Start alice, the SSL client"
python alice.py alice_run.cfg test_transmission.txt

