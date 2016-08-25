'''
Generate data
'''

import os, sys

#------------ Begin Main Program ------------------------------------
if __name__ == "__main__":

	if len(sys.argv) != 4:
		print("Usage: python   datagen.py   target-file   record-size   record-count")
		sys.exit(86)

	output_file = sys.argv[1]
	try:
		record_size = int(sys.argv[2])
	except:
		util.oops("Specified record size {%s} is not an integer", record_size)
	if record_size < 8 or record_size > 2000:
		util.oops("Record size must be in the range of 8 to 2000")
	try:
		record_count = int(sys.argv[3])
	except:
		util.oops("Specified record count {%s} is not an integer", record_count)
	if record_count < 1 or record_count > 10000:
		util.oops("Record count must be in the range of 1 to 10000")

	try:
		fd = open(output_file, "w")
	except Exception as err:
		util.oops("Failed to open {%s} for writing, reason: {%s}", output_file, repr(err))

	try:
		for ndx in range(1, (record_count + 1)):
			for nbytes in range(1, record_size):
				fd.write('*')
			fd.write('\n')
	except Exception as err:
		util.oops(" File write failed, reason: {%s}", repr(err))

	try:
		fd.close()
	except Exception as err:
		util.oops(" File close failed, reason: {%s}", repr(err))

