#!/usr/bin/python

import glob, sqlite, sys, re, os, string, shutil
import sarahlib

from xml.dom.ext.reader import Sax2
from xml.dom.NodeFilter import NodeFilter

con, cur = sarahlib.opendb()

### Unbuffered sys.stdout
sys.stdout = os.fdopen(1, 'w', 0)

cur.execute('select distinct advid from adv order by advid')
print 'Number of advisories:', len(cur.fetchall())

cur.execute('select distinct advid from adv where severitylevel = "critical"')
print '\tcritical:', len(cur.fetchall()), '/',
cur.execute('select distinct advid from adv where severitylevel = "important"')
print 'important:', len(cur.fetchall()), '/',
cur.execute('select distinct advid from adv where severitylevel = "moderate"')
print 'moderate:', len(cur.fetchall()), '/',
cur.execute('select distinct advid from adv where severitylevel = "low"')
print 'low:', len(cur.fetchall()), '/',
cur.execute('select distinct advid from adv where severitylevel = "unknown"')
print 'unknown:', len(cur.fetchall())

cur.execute('select typeshort from typ order by typeshort')
print 'Number of types:', len(cur.fetchall())

### Debug database
#cur.execute('select * from adv order by advid')
#for all in cur.fetchall():
#	print all

#cur.execute('select distinct advid from adv where severitylevel = "unknown" order by advid')
#print cur.fetchall()
