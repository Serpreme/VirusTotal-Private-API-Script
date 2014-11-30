#!/usr/bin/env python
import subprocess
import re
f1 = open('result.txt', 'r+')
f2 = open('leftover.txt', 'r+')
command = ("/vol/v.py driverscan -f s.vmem --output-file=drivedmp.txt")
subprocess.call(command, shell=True)
for line in open("drivedmp.txt"):
	columns = line.split( )
	if len(columns) >= 2:
 	print(columns[5], end='\n', file=f1)
with open('drivecontrol.txt') as b:
  blines = set(b)
with open('result.txt') as a:
  with open('leftover.txt', 'w') as result:
	for line in a:
  	if line not in blines:
    	f2.write(line)

