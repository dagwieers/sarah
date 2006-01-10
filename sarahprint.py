#!/usr/bin/python

import glob, sqlite, sys, re, os, string, shutil
from xml.dom.ext.reader import Sax2
from xml.dom.NodeFilter import NodeFilter

import sarahlib

advcon, advcur = sarahlib.opendb('adv')
refcon, refcur = sarahlib.opendb('ref')
rpmcon, rpmcur = sarahlib.opendb('rpm')
procon, procur = sarahlib.opendb('pro')
typcon, typcur = sarahlib.opendb('typ')

### Unbuffered sys.stdout
sys.stdout = os.fdopen(1, 'w', 0)

advcur.execute('select distinct advid from adv order by advid')
print 'Number of advisories:', len(advcur.fetchall())

advcur.execute('select distinct advid from adv where severitylevel = "critical"')
print '\tcritical:', len(advcur.fetchall()),
advcur.execute('select distinct advid from adv where severitylevel = "important"')
print 'important:', len(advcur.fetchall()),
advcur.execute('select distinct advid from adv where severitylevel = "moderate"')
print 'moderate:', len(advcur.fetchall()),
advcur.execute('select distinct advid from adv where severitylevel = "low"')
print 'low:', len(advcur.fetchall()),
advcur.execute('select distinct advid from adv where severitylevel = "unknown"')
print 'unknown:', len(advcur.fetchall()),
print

typcur.execute('select typeshort from typ order by typeshort')
print 'Number of types:', len(typcur.fetchall())

### Debug database
#advcur.execute('select * from adv order by advid')
#for all in advcur.fetchall():
#	print all
