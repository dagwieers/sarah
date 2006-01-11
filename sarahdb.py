#!/usr/bin/python

import sys, os, glob, sqlite
import sarahlib

from xml.dom.ext.reader import Sax2
from xml.dom.NodeFilter import NodeFilter
import xml.sax

sys.stdout = os.fdopen(1, 'w', 0)

con, cur = sarahlib.opendb()
sarahlib.createtb(cur, 'adv')
sarahlib.createtb(cur, 'ref')
sarahlib.createtb(cur, 'rpm')
sarahlib.createtb(cur, 'pro')
sarahlib.createtb(cur, 'typ')

reader = Sax2.Reader()

filelist = glob.glob('advisories/RHSA-*.xml')
#filelist = glob.glob('advisories/RHSA-2005-812.xml')
filelist.sort()

for file in filelist:
	try:
		doc = reader.fromStream(open(file))
		walker = doc.createTreeWalker(doc.documentElement, NodeFilter.SHOW_ELEMENT, None, 0)
	except xml.sax._exceptions.SAXParseException:
		print '\033[0;31m%s\033[0;0m' % os.path.basename(file),
		continue

	print os.path.basename(file).strip('.xml'),

	next = True
	advrec = {};
	while next is not None:
#		print walker.currentNode.tagName

		if walker.currentNode.tagName == 'advisory':
			advrec['sender'] = walker.currentNode.getAttribute('sender')
			advrec['version'] = walker.currentNode.getAttribute('version')

		elif walker.currentNode.tagName == 'id':
			advrec['advid'] = walker.currentNode.firstChild.data

		elif walker.currentNode.tagName == 'pushcount':
			advrec['pushcount'] = int(walker.currentNode.firstChild.data)

		elif walker.currentNode.tagName == 'type':
			typrec = advrec.copy()
			typrec['type'] = walker.currentNode.firstChild.data
			advrec['typeshort'] = typrec['typeshort'] = walker.currentNode.getAttribute('short')
			cur.execute('select type from typ where typeshort = "%(typeshort)s"' % typrec)
			typelist = [type for type, in cur.fetchall()]
			if not typelist:
				sarahlib.insertrec(cur, 'typ', typrec)
				con.commit()
			elif typrec['type'] not in typelist:
				print 'ERROR: Wrong type exists (%s not in %s)' % (typrec['type'], typelist)

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
			next = walker.nextNode()
			while walker.currentNode.tagName == 'reference':
				refrec = advrec.copy()
				refrec['reftype'] = walker.currentNode.getAttribute('type')
				if refrec['reftype'] == 'self':
					refrec['reference'] = walker.currentNode.firstChild.data
					refrec['cve'] = None
				elif refrec['reftype'] == 'cve':
					refrec['reference'] = walker.currentNode.getAttribute('href')
					refrec['cve'] = walker.currentNode.firstChild.firstChild.data
				sarahlib.insertrec(cur, 'ref', refrec)
				con.commit()
				next = walker.nextNode()
			continue

		elif walker.currentNode.tagName == 'topic':
			advrec['topic'] = walker.currentNode.firstChild.data

		elif walker.currentNode.tagName == 'description':
			advrec['description'] = walker.currentNode.firstChild.data

		elif walker.currentNode.tagName == 'rpmlist':
			next = walker.nextNode()
			while walker.currentNode.tagName == 'product':
				prorec = advrec.copy()
				prorec['prodshort'] = walker.currentNode.getAttribute('short')
				### FIXME: Do proper nested parsing
				next = walker.nextNode()
				prorec['product'] = walker.currentNode.firstChild.data
				### FIXME: Create a unique insert function
				try: sarahlib.insertrec(cur, 'pro', prorec)
				except: pass
				next = walker.nextNode()
				while walker.currentNode.tagName == 'file':
					rpmrec = advrec
					rpmrec['arch'] = walker.currentNode.getAttribute('arch')
					rpmrec['prodshort'] = prorec['prodshort']
					### FIXME: Do proper nested parsing
					next = walker.nextNode()
					while walker.currentNode.tagName == 'filename':
						rpmrec['filename'] = walker.currentNode.firstChild.data
						next = walker.nextNode()
					while walker.currentNode.tagName == 'sum':
						rpmrec['md5'] = walker.currentNode.firstChild.data
						next = walker.nextNode()
					sarahlib.insertrec(cur, 'rpm', rpmrec)
				continue
				con.commit()
			continue

		next = walker.nextNode()

	sarahlib.insertrec(cur, 'adv', advrec)
	con.commit()
