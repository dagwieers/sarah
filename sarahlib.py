import os, sqlite, types

dbase = 'sarahdb.sqlite'

headers = {
#	'adv': ('advid', 'pushcount', 'severitylevel', 'issuedate', 'updatedate', 'type', 'synopsis', 'description', 'topic', 'sender', 'version'),
	'adv': ('advid', 'pushcount', 'severitylevel', 'issuedate', 'updatedate', 'type', 'synopsis', 'description', 'topic'),
	'ref': ('advid', 'reftype', 'reference', 'id', 'summary'),
	'rpm': ('advid', 'prodshort', 'arch', 'filename', 'md5'),
	'pro': ('prodshort', 'product'),
}

dataopts = {
	'adv': { 'advid': 'unique primary key', },
#	'ref': { 'reftype': 'unique primary key', },
#	'rpm': { 'filename': 'unique primary key', },
	'pro': { 'prodshort': 'unique primary key', },
}

def sqlcreate(name):
	'Return a database create SQL statement'
	str = 'create table %s ( ' % name
	for key in headers[name]:
		ds = ''
		if dataopts.has_key(name) and dataopts[name].has_key(key):
			ds = dataopts[name][key]
		str += '%s varchar(10) %s,' % (key, ds)
	return str.rstrip(', ') + ' )'

def sqlinsert(name):
	'Return a database insert SQL statement'
	str = 'insert into %s ( ' % name
	for key in headers[name]: str += '%s, ' % key
	str = str.rstrip(', ') + ' ) values ( '
	for key in headers[name]: str += '"%%(%s)s", ' % key
	return str.rstrip(', ') + ' )'

def opendb():
	'Open a database and return references'
	con = sqlite.connect(dbase)
	cur = con.cursor()
	return con, cur

def createtb(cur, name, create=False):
	try: cur.execute('drop table "%s"' % name)
	except: pass
	cur.execute(sqlcreate(name))

def insertrec(cur, name, rec):
	'Insert a record in a database'
	### Convert unicode to UTF-8
	for key in rec.keys():
		if isinstance(rec[key], types.UnicodeType):
			rec[key] = rec[key].encode('utf-8')
	cur.execute(sqlinsert(name) % rec)
