#!/usr/bin/python

import glob, sqlite, sys, re, os, string, shutil
import sarahlib

from xml.dom.ext.reader import Sax2
from xml.dom.NodeFilter import NodeFilter

sys.stdout = os.fdopen(1, 'w', 0)
con, cur = sarahlib.opendb()

cur.execute('select severitylevel from adv')
advlist = cur.fetchall()
print 'Number of advisories:', len(advlist)
count = {}
for adv, in advlist:
	if not count.has_key(adv): count[adv] = 0
	count[adv] += 1
print '  ', 
for key in ('critical', 'important', 'moderate', 'low', 'unknown'):
	if key in count.keys():
		print '%s: %s  ' % (key, count[key]),
print
print

cur.execute('select typeshort from typ order by typeshort')
typelist = [e for e, in cur.fetchall()]
print 'Number of types:', len(typelist)
print '  ', string.join(typelist, ', ')
print

cur.execute('select prodshort from pro order by prodshort')
prodlist = [e for e, in cur.fetchall()]
print 'Number of products:', len(prodlist)
print '  ', string.join(prodlist, ', ')
print

print 'Distribution of advisories:'
for prod in prodlist:
	cur.execute('select distinct advid from rpm where prodshort == "%s"' % prod)
	print '  ', prod, 'has', len(cur.fetchall()), 'advisories'
print

cur.execute('select distinct filename from rpm order by filename')
print 'Number of files:', len(cur.fetchall())
print

cur.execute('select reftype from ref')
reflist = cur.fetchall()
print 'Number of references:', len(reflist)
count = {}
for ref, in reflist:
	if not count.has_key(ref): count[ref] = 0
	count[ref] += 1
print '  ', 
for key in count.keys():
	print '%s: %s  ' % (key, count[key]),
print
print

### Calculate average length of datatypes
#for table in ('adv', 'ref', 'rpm', 'pro', 'typ'):
#	for header in sarahlib.headers[table]:
#		cur.execute('select %s from %s' % (header, table))
#		list = cur.fetchall()
#		lenght = 0
#		for value, in list:
#			lenght += len(value)
#		print table, header, lenght / len(list)

### Debug database
#cur.execute('select * from adv order by advid')
#for all in cur.fetchall():
#	print all

#cur.execute('select distinct advid from adv where severitylevel = "unknown" order by advid')
#print cur.fetchall()

#cur.execute('select * from pro')
#print cur.fetchall()

#cur.execute('select * from rpm where advid == "RHSA-2005:812" order by advid, filename')
#for all in cur.fetchall():
#	print all
