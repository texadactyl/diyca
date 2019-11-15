import time, os, sys

# Generic logger using a C printf API
# Prepend a standard-format time stamp to the supplied arguments
def logger(arg_format, *arg_list):
	now = time.strftime("%Y-%m-%d %H:%M:%S ", time.localtime())
	fmt = "{nstr} {fstr}".format(nstr=now, fstr=arg_format)
	buffer = fmt %arg_list
	print(buffer)

# Log and abort
def oops(arg_format, *arg_list):
	logger ("*** Oops, " + arg_format, *arg_list )
	sys.exit(86)


