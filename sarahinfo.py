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

cur.execute('select severity from adv where type == "RHSA"')
advlist = cur.fetchall()
print 'Security advisory per severity:'
count = {}
for adv, in advlist:
	if not count.has_key(adv): count[adv] = 0
	count[adv] += 1
print '  ', 
for key in ('critical', 'important', 'moderate', 'low', 'unknown', 'error'):
	if key in count.keys():
		print '%s: %s  ' % (key, count[key]),
print
print

cur.execute('select distinct advid, prodshort from rpm')
prodlist = cur.fetchall()
print 'Advisories per products'
count = {}
for advid, prod in prodlist:
	if not count.has_key(prod): count[prod] = 0
	count[prod] += 1
print '  ', 
for key in ('2.1AS', '2.1ES', '2.1WS', '2.1AW'):
	if key in count.keys():
		print '%s: %s  ' % (key, count[key]),
print '\n  ', 
for key in ('3AS', '3ES', '3WS', '3Desktop'):
	if key in count.keys():
		print '%s: %s  ' % (key, count[key]),

print '\n  ', 
for key in ('4AS', '4ES', '4WS', '4Desktop'):
	if key in count.keys():
		print '%s: %s  ' % (key, count[key]),
print
print

print 'Advisories per year:'
print '  ',
for year in ('2002', '2003', '2004', '2005', '2006'):
	cur.execute('select advid from adv where issued glob "*%s*"' % year)
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

#cur.execute('select distinct advid from adv where severity = "unknown" order by advid')
#print cur.fetchall()

#cur.execute('select * from pro')
#print cur.fetchall()

#cur.execute('select * from rpm where advid == "RHSA-2005:812" order by advid, filename')
#for all in cur.fetchall():
#	print all
