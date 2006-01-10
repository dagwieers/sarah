#!/usr/bin/python

import glob, sqlite, sys, re, os, string, shutil
from xml.dom.ext.reader import Sax2
from xml.dom.NodeFilter import NodeFilter
import xml.sax

import sarahlib

sys.stdout = os.fdopen(1, 'w', 0)

con, cur = sarahlib.opendb()
sarahlib.createtb(cur, 'adv')
sarahlib.createtb(cur, 'ref')
sarahlib.createtb(cur, 'rpm')
sarahlib.createtb(cur, 'pro')
sarahlib.createtb(cur, 'typ')

reader = Sax2.Reader()

filelist = glob.glob('advisories/RHSA-*.xml')
filelist.sort()

for file in filelist:
	try:
		doc = reader.fromStream(open(file))
		walker = doc.createTreeWalker(doc.documentElement, NodeFilter.SHOW_ELEMENT, None, 0)
	except xml.sax._exceptions.SAXParseException:
		print '**%s**' % os.path.basename(file),
		continue

	print os.path.basename(file),

	next = True
	advrec = {}; prorec ={}; typrec = {}
	while next is not None:
#		print walker.currentNode.tagName

		if walker.currentNode.tagName == 'id':
			advrec['advid'] = walker.currentNode.firstChild.data

		elif walker.currentNode.tagName == 'advisory':
			advrec['sender'] = walker.currentNode.getAttribute('sender')
			advrec['version'] = walker.currentNode.getAttribute('version')

		elif walker.currentNode.tagName == 'pushcount':
			advrec['pushcount'] = int(walker.currentNode.firstChild.data)

		elif walker.currentNode.tagName == 'type':
			typrec['type'] = walker.currentNode.firstChild.data
			advrec['typeshort'] = typrec['typeshort'] = walker.currentNode.getAttribute('short')
			cur.execute('select type from typ where typeshort = "%(typeshort)s"' % typrec)
			typelist = [type for type, in cur.fetchall()]
			if not typelist:
				sarahlib.insertrec(cur, 'typ', typrec)
				con.commit()
			elif typrec['type'] not in typelist:
				print "ERROR: Wrong type exists (%s not in %s)" % (typrec['type'], typelist)

		elif walker.currentNode.tagName == 'severity':
			if walker.currentNode.firstChild.data:
				advrec['severitylevel'] = walker.currentNode.firstChild.data
			elif walker.currentNode.getAttribute('level'):
				advrec['severitylevel'] = walker.currentNode.getAttribute('level')
			else:
				advrec['severitylevel'] = 'error'

		elif walker.currentNode.tagName == 'synopsis':
			advrec['synopsis'] = walker.currentNode.firstChild.data

		elif walker.currentNode.tagName == 'issued':
			advrec['issuedate'] = walker.currentNode.getAttribute('date')

		elif walker.currentNode.tagName == 'updated':
			advrec['updatedate'] = walker.currentNode.getAttribute('date')

		elif walker.currentNode.tagName == 'references':
			pass

		elif walker.currentNode.tagName == 'topic':
			advrec['topic'] = walker.currentNode.firstChild.data

		elif walker.currentNode.tagName == 'description':
			advrec['description'] = walker.currentNode.firstChild.data

		elif walker.currentNode.tagName == 'rpmlist':
			pass

		elif walker.currentNode.tagName == 'product':
			prorec['product'] = ''
			advrec['productshort'] = ''

		elif walker.currentNode.tagName == 'product':
			prorec['product'] = walker.currentNode.firstChild.data
			advrec['productshort'] = pro['productshort'] = walker.currentNode.getAttribute('short')
			procur.execute('select product, productshort from pro where productshort = "%(productshort)s"' % prorec)
			if procur.fetchall():
				for productshort, product in procur.fetchall():
					if product != prorec['product']:
						print "ERROR: Wrong product exists (%s != %s)" % prorec['product'], product
			else:
				sarahlib.insertrec(cur, 'pro', prorec)
				con.commit()
		next = walker.nextNode()

#	print advrec

	sarahlib.insertrec(cur, 'adv', advrec)
	con.commit()
