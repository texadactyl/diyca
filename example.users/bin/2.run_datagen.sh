
cd alice
if [ $? -ne 0 ]; then
	echo "*** $MYNAME: failed to cd to alice"
	exit 86
fi

# record size = 256
# Record count = 10000
python datagen.py test_transmission.txt 256 10000
