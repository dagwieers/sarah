#!/usr/bin/python

import sys, os, glob, sqlite
import sarahlib

from xml.dom.ext.reader import Sax2
from xml.dom.NodeFilter import NodeFilter
import xml.sax

def handle_walker(walker):
	next = walker.nextNode()
	node = walker.currentNode
	return node, next

sys.stdout = os.fdopen(1, 'w', 0)

con, cur = sarahlib.opendb()
sarahlib.createtb(cur, 'adv')
sarahlib.createtb(cur, 'ref')
sarahlib.createtb(cur, 'rpm')
sarahlib.createtb(cur, 'pro')

reader = Sax2.Reader()

filelist = glob.glob('advisories/RH?A-*.xml')
#filelist = glob.glob('advisories/RHSA-*.xml')
#filelist = ['advisories/RHSA-2005-791.xml', ]
filelist.sort()

for file in filelist:
	try:
		doc = reader.fromStream(open(file))
		walker = doc.createTreeWalker(doc.documentElement, NodeFilter.SHOW_ELEMENT, None, 0)

		next = True
		node = walker.currentNode
		advrec = {};
		while next is not None:
#			print node.tagName
	
			if node.tagName == 'advisory':
				advrec['sender'] = node.getAttribute('sender')
				advrec['version'] = node.getAttribute('version')
	
			elif node.tagName == 'id':
				advrec['advid'] = node.firstChild.data
	
			elif node.tagName == 'pushcount':
				advrec['pushcount'] = int(node.firstChild.data)
	
			elif node.tagName == 'type':
				advrec['type'] = node.getAttribute('short')

			elif node.tagName == 'keywords':
				if hasattr(node.firstChild, 'data'):
					advrec['keywords'] = node.firstChild.data

			elif node.tagName == 'obsoletes':
				advrec['obsoletes'] = node.firstChild.data

			elif node.tagName == 'group':
				advrec['rhgroup'] = node.getAttribute('name')

			elif node.tagName == 'severity':
				if node.hasAttribute('level'):
					advrec['severity'] = node.getAttribute('level')
				elif node.firstChild.data:
					advrec['severity'] = node.firstChild.data
				else:
					advrec['severity'] = 'error'
	
			elif node.tagName == 'synopsis':
				advrec['synopsis'] = node.firstChild.data
	
			elif node.tagName == 'issued':
				advrec['issued'] = node.getAttribute('date')
	
			elif node.tagName == 'updated':
				advrec['updated'] = node.getAttribute('date')
	
			elif node.tagName == 'references':
				node, next = handle_walker(walker)
				while node.tagName == 'reference':
					refrec = advrec.copy()

					if node.hasAttribute('type'):
						refrec['reftype'] = node.getAttribute('type')

					if node.hasAttribute('href'):
						refrec['reference'] = node.getAttribute('href')

					node, next = handle_walker(walker)
					while node.tagName in ('advisory', 'bugzilla', 'cve', 'summary'):
						if node.tagName in ('advisory', 'bugzilla', 'cve'):
							refrec['refid'] = node.firstChild.data
						elif node.tagName == 'summary':
							refrec['summary'] = node.firstChild.data
						else:
							raise 'Unknown tag <%s> in reference node' % node.tagName
						node, next = handle_walker(walker)

					if refrec['reftype'] == 'self':
						refrec['refid'] = advrec['advid']

					if not refrec.has_key('summary'):
						refrec['summary'] = None

					if not refrec.has_key('id'):
						refrec['refid'] = None

					sarahlib.insertrec(cur, 'ref', refrec)
				con.commit()
				continue
	
			elif node.tagName == 'topic':
				advrec['topic'] = node.firstChild.data
	
			elif node.tagName == 'description':
				advrec['description'] = node.firstChild.data
	
			elif node.tagName == 'rpmlist':
				node, next = handle_walker(walker)
				while node.tagName == 'product':
					prorec = advrec.copy()
					prorec['prodshort'] = node.getAttribute('short')
					### FIXME: Do proper nested parsing
					node, next = handle_walker(walker)
					prorec['product'] = node.firstChild.data
					### FIXME: Create a unique insert function
					try: sarahlib.insertrec(cur, 'pro', prorec)
					except: pass
					node, next = handle_walker(walker)
					while node.tagName == 'file':
						rpmrec = advrec.copy()
						rpmrec['arch'] = node.getAttribute('arch')
						rpmrec['prodshort'] = prorec['prodshort']
						rpmrec['channels'] = []
						### FIXME: Do proper nested parsing
						node, next = handle_walker(walker)
						while node.tagName in ('filename', 'sum', 'channel'):
							if node.tagName == 'filename':
								rpmrec['filename'] = node.firstChild.data
							elif node.tagName == 'sum':
								rpmrec['md5'] = node.firstChild.data
							elif node.tagName == 'channel':
								rpmrec['channels'].append(node.getAttribute('name'))
							else:
								raise 'Unknown tag <%s> in file node' % node.tagName
							node, next = handle_walker(walker)
						sarahlib.insertrec(cur, 'rpm', rpmrec)
				con.commit()
				continue

			elif node.tagName in ('a', 'contact', 'p', 'product', 'rights', 'rpmtext', 'solution'):
				pass

			else:
				print 'Unknown tag <%s> in advisory node' % str(node.tagName)
	
			node, next = handle_walker(walker)

		### RHBAs and RHEAs do not have a severity level
		if advrec['type'] in ('RHBA', 'RHEA'):
			advrec['severity'] = None
		if not advrec.has_key('severity'):
			advrec['severity'] = 'unknown'

		if not advrec.has_key('severity'): advrec['severity'] = 'unknown'
		if not advrec.has_key('rhgroup'): advrec['rhgroup'] = None
		if not advrec.has_key('keywords'): advrec['keywords'] = None
		if not advrec.has_key('obsoletes'): advrec['obsoletes'] = None
	
		sarahlib.insertrec(cur, 'adv', advrec)
#		con.commit()

		print '\033[0;32m%s\033[0;0m' % os.path.basename(file).strip('.xml'),

	except (xml.sax._exceptions.SAXParseException, AttributeError, KeyError), e:
		print '\033[0;31m%s\033[0;0m' % os.path.basename(file),
		print e
		raise
#		continue
con.commit()
