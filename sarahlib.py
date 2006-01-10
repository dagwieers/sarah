import os, sqlite, types

dbase = 'sarahdb.sqlite'

headers = {
#	'adv': ('advid', 'pushcount', 'severitylevel', 'issuedate', 'updatedate', 'typeshort', 'synopsis', 'description', 'topic', 'sender', 'version'),
	'adv': ('advid', 'pushcount', 'severitylevel', 'issuedate', 'updatedate', 'typeshort', 'synopsis', 'description', 'topic'),
	'ref': ('advid', 'reftype', 'reference'),
	'rpm': ('advid', 'prodshort', 'arch', 'filename', 'md5'),
	'pro': ('productshort', 'product'),
	'typ': ('typeshort', 'type'),
}

dataset = {
	'spec': { 'name': 'varchar(10) unique primary key', },
	'info': { 'name': 'varchar(10) unique primary key', },
}

def sqlcreate(name):
	'Return a database create SQL statement'
	str = 'create table %s ( ' % name
	for key in headers[name]:
		if dataset.has_key(name) and dataset[name].has_key(key):
			str += '%s %s,' % (key, dataset[name][key])
		else:   
			str += '%s varchar(10), ' % key
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
