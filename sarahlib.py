import os, sqlite, types

dbase = {
	'adv': 'sarahdb/Advisories.sqlite',
	'ref': 'sarahdb/References.sqlite',
	'rpm': 'sarahdb/RPMList.sqlite',
	'pro': 'sarahdb/Products.sqlite',
	'typ': 'sarahdb/Types.sqlite',
}

headers = {
#	'adv': ('advid', 'pushcount', 'severitylevel', 'issuedate', 'updatedate', 'typeshort', 'synopsis', 'description', 'topic', 'sender', 'version'),
	'adv': ('advid', 'pushcount', 'severitylevel', 'issuedate', 'updatedate', 'typeshort', 'synopsis', 'description', 'topic'),
	'ref': ('advid', 'reftype', 'reference'),
	'rpm': ('advid', 'prodshort', 'arch', 'filename', 'md5'),
	'pro': ('productshort', 'product'),
	'typ': ('typeshort', 'type'),
}

def sqlcreate(name):
	'Return a database create SQL statement'
	str = 'create table %s ( ' % name
	for key in headers[name]: str += '%s varchar(10), ' % key
	return str.rstrip(', ') + ' )'

def sqlinsert(name):
	'Return a database insert SQL statement'
	str = 'insert into %s ( ' % name
	for key in headers[name]: str += '%s, ' % key
	str = str.rstrip(', ') + ' ) values ( '
	for key in headers[name]: str += '"%%(%s)s", ' % key
	return str.rstrip(', ') + ' )'

def opendb(name, create=False):
	'Open a database and return references'
	con = sqlite.connect(dbase[name])
	cur = con.cursor()
	if create:
		cur.execute(sqlcreate(name))
	return (con, cur)

def insertdb(cur, name, rec):
	'Insert a record in a database'
	### Convert unicode to UTF-8
	for key in rec.keys():
		if isinstance(rec[key], types.UnicodeType):
			rec[key] = rec[key].encode('utf-8')
	cur.execute(sqlinsert(name) % rec)
