"""
Bob's utilities
"""
import time
import sys

def logger(arg_format, *arg_list):
    """
    Generic logger using a C printf API.
    Prepend a standard-format time stamp to the supplied arguments.
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S ", time.localtime())
    fmt = "{nstr} {fstr}".format(nstr=now, fstr=arg_format)
    buffer = fmt %arg_list
    print(buffer)

# Log and abort
def oops(arg_format, *arg_list):
    """
    Log and error message and then abort.
    """
    logger("*** Oops, " + arg_format, *arg_list)
    sys.exit(86)
