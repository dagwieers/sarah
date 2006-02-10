#!/usr/bin/python

import sys, os, sqlite, string
import sarahlib

sys.stdout = os.fdopen(1, 'w', 0)
con, cur = sarahlib.opendb()

cur.execute('select advid from adv')
advlist = cur.fetchall()
print 'Number of advisories:', len(advlist)
print

cur.execute('select distinct type from adv order by type')
typelist = [e for e, in cur.fetchall()]
print 'Advisories per type:'
print '  ',
for type in typelist:
	cur.execute('select distinct advid from adv where type == "%s"' % type)
	print '%s: %s  ' % (type, len(cur.fetchall())),
print
print

cur.execute('select severitylevel from adv where type == "RHSA"')
advlist = cur.fetchall()
print 'Security advisory per severity level:'
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

cur.execute('select prodshort from pro order by prodshort')
prodlist = [e for e, in cur.fetchall()]
print 'Advisories per products'
last = '2'
print '  ',
for prod in prodlist:
	if last != prod[0]:
		print '\n  ',
		last = prod[0]
	cur.execute('select distinct advid from rpm where prodshort == "%s"' % prod)
	print '%s: %s \t' % (prod, len(cur.fetchall())),
print
print

print 'Advisories per year:'
print '  ',
for year in ('2002', '2003', '2004', '2005', '2006'):
	cur.execute('select advid from adv where issuedate glob "*%s*"' % year)
	print '%s: %s \t' % (year, len(cur.fetchall())),
print
print

cur.execute('select reftype from ref order by reftype')
typelist = cur.fetchall()
print 'Number of references:', len(typelist)
count = {}
for type, in typelist:
	if not count.has_key(type): count[type] = 0
	count[type] += 1
print '  ', 
keys = count.keys()
keys.sort()
for key in keys:
	print '%s: %s  ' % (key, count[key]),
print
print

cur.execute('select distinct filename from rpm order by filename')
print 'Number of files:', len(cur.fetchall())
print

### Calculate average length of datatypes
#for table in ('adv', 'ref', 'rpm', 'pro'):
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
