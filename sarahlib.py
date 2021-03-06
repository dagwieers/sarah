import os, types
import sqlite

dbase = 'sarahdb.sqlite'

headers = {
#	'adv': ('advid', 'pushcount', 'severity', 'issued', 'updated', 'type', 'synopsis', 'description', 'topic', 'sender', 'version'),
	'adv': ('advid', 'pushcount', 'severity', 'issued', 'updated', 'type', 'synopsis', 'description', 'topic', 'keywords', 'rhgroup', 'obsoletes'),
	'ref': ('advid', 'reftype', 'reference', 'refid', 'summary'),
#	'rpm': ('advid', 'prodshort', 'arch', 'filename', 'md5', 'channels'),
	'rpm': ('advid', 'prodshort', 'arch', 'filename', 'md5'),
	'pro': ('prodshort', 'product'),
}

dataopts = {
	'adv': { 'advid': 'unique primary key', 'pushcount': 'integer'},
#	'ref': { 'refid': 'unique primary key', },
#	'rpm': { 'filename': 'unique primary key', 'md5': 'unique'},
#	'rpm': { 'filename': 'unique primary key',},
	'pro': { 'prodshort': 'unique primary key', 'product': 'unique'},
}


### Build insert strings for each database
insertstr = { }
for name in headers.keys():
	insertstr[name] = 'insert into %s ( ' % name
	for key in headers[name]: insertstr[name] += '%s, ' % key
	insertstr[name] = insertstr[name].rstrip(', ') + ' ) values ( ' + '%s, ' * len(headers[name])
	insertstr[name] = insertstr[name].rstrip(', ') + ' )'

def sqlcreate(name):
	'Return a database create SQL statement'
	str = 'create table %s ( ' % name
	for key in headers[name]:
		if dataopts.has_key(name) and dataopts[name].has_key(key):
			str += '%s %s,' % (key, dataopts[name][key])
		else:
			str += '%s varchar(10),' % key
	return str.rstrip(', ') + ' )'

#def sqlinsert(name):
#	'Return a database insert SQL statement'
#	str = 'insert into %s ( ' % name
#	for key in headers[name]: str += '%s, ' % key
#	str = str.rstrip(', ') + ' ) values ( '
#	for key in headers[name]: str += '"%%(%s)s", ' % key
#	return str.rstrip(', ') + ' )'

def opendb():
	'Open a database and return references'
	con = sqlite.connect(dbase)
	cur = con.cursor()
	return con, cur

def createtb(cur, name, create=False):
	try:
		cur.execute('drop table "%s"' % name)
	except Exception, e: 
#		print e
		pass
	cur.execute(sqlcreate(name))

def insertrec(cur, name, rec):
	'Insert a record in a database'
	global insertstr

	values = []
	for key in headers[name]:
		### Convert unicode to UTF-8
		if isinstance(rec[key], types.UnicodeType):
			rec[key] = rec[key].encode('utf-8')
		values.append(rec[key])
#	print insertstr[name]
#	print values
	cur.execute(insertstr[name], values)
