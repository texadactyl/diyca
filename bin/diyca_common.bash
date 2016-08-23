### diyca common bash procedures

check_subdir () {
	#logger -s -t $1 "Checking $2 ..."
	if [ ! -d $2 ]; then
		logger -s -t $1 "*** Subdirectory $2 is inaccessible"
		exit 86
	fi
}

diyca_validate_tree () {
	VALIDATOR="diyca_validate_tree"
	if [ ! -r allow_nonroot ]; then
		USERID=`id -u $USER`
		if [ $USERID -ne 0 ]; then
			logger -s -t $VALIDATOR "*** Expected User ID = 0; observed USER=$USER, ID=$USERID"
			exit 86
		fi
	fi
	#logger -s -t $VALIDATOR "validate_diyca: Begin"
	if [ ! -r diyca.version ]; then
		logger -s -t $VALIDATOR "*** diy.ssl.ca.version is inaccessible"
		exit 86
	fi
	check_subdir $VALIDATOR "app_web"
	check_subdir $VALIDATOR "app_web/static"
	check_subdir $VALIDATOR "app_web/templates"
	check_subdir $VALIDATOR "bin"
	check_subdir $VALIDATOR "calvin"
	check_subdir $VALIDATOR "docs"
	#logger -s -t $VALIDATOR "validate_diyca: Successful"
}
