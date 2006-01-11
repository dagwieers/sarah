#!/usr/bin/python

import sys, os, sqlite, string
import sarahlib

sys.stdout = os.fdopen(1, 'w', 0)
con, cur = sarahlib.opendb()

query = string.join(sys.argv[1:], ' ')
cur.execute(query)
for rec in cur.fetchall():
	for col in rec:
		print '%s\t' % col,
	print
