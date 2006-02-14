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
		advrec = {};
		while next is not None:
#			print walker.currentNode.tagName
	
			if walker.currentNode.tagName == 'advisory':
				advrec['sender'] = walker.currentNode.getAttribute('sender')
				advrec['version'] = walker.currentNode.getAttribute('version')
	
			elif walker.currentNode.tagName == 'id':
				advrec['advid'] = walker.currentNode.firstChild.data
	
			elif walker.currentNode.tagName == 'pushcount':
				advrec['pushcount'] = int(walker.currentNode.firstChild.data)
	
			elif walker.currentNode.tagName == 'type':
				advrec['type'] = walker.currentNode.getAttribute('short')

			elif walker.currentNode.tagName == 'severity':
				if walker.currentNode.hasAttribute('level'):
					advrec['severitylevel'] = walker.currentNode.getAttribute('level')
				elif walker.currentNode.firstChild.data:
					advrec['severitylevel'] = walker.currentNode.firstChild.data
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

					if walker.currentNode.hasAttribute('type'):
						refrec['reftype'] = walker.currentNode.getAttribute('type')

					if walker.currentNode.hasAttribute('href'):
						refrec['reference'] = walker.currentNode.getAttribute('href')

					next = walker.nextNode()
					while walker.currentNode.tagName in ('advisory', 'bugzilla', 'cve', 'summary'):
						if walker.currentNode.tagName in ('advisory', 'bugzilla', 'cve'):
							refrec['id'] = walker.currentNode.firstChild.data
						elif walker.currentNode.tagName == 'summary':
							refrec['summary'] = walker.currentNode.firstChild.data
						else:
							raise 'Unknown tag in reference node'
						next = walker.nextNode()

					if refrec['reftype'] == 'self':
						refrec['id'] = advrec['advid']

					if not refrec.has_key('summary'):
						refrec['summary'] = None

					if not refrec.has_key('id'):
						refrec['id'] = None

					sarahlib.insertrec(cur, 'ref', refrec)
				con.commit()
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
						rpmrec = advrec.copy()
						rpmrec['arch'] = walker.currentNode.getAttribute('arch')
						rpmrec['prodshort'] = prorec['prodshort']
						rpmrec['channel'] = []
						### FIXME: Do proper nested parsing
						next = walker.nextNode()
						while walker.currentNode.tagName in ('filename', 'sum', 'channel'):
							if walker.currentNode.tagName == 'filename':
								rpmrec['filename'] = walker.currentNode.firstChild.data
							elif walker.currentNode.tagName == 'sum':
								rpmrec['md5'] = walker.currentNode.firstChild.data
							elif walker.currentNode.tagName == 'channel':
								rpmrec['channel'].append(walker.currentNode.getAttribute('name'))
							else:
								raise 'Unknown tag in file node'
							next = walker.nextNode()
						sarahlib.insertrec(cur, 'rpm', rpmrec)
				con.commit()
				continue
	
			next = walker.nextNode()

		### RHBAs and RHEAs do not have a severity level
		if advrec['type'] in ('RHBA', 'RHEA'):
			advrec['severitylevel'] = None
		if not advrec.has_key('severitylevel'):
			advrec['severitylevel'] = 'unknown'
	
		sarahlib.insertrec(cur, 'adv', advrec)
#		con.commit()

		print '\033[0;32m%s\033[0;0m' % os.path.basename(file).strip('.xml'),

	except (xml.sax._exceptions.SAXParseException, AttributeError, KeyError), e:
		print '\033[0;31m%s\033[0;0m' % os.path.basename(file),
		print e
#		raise
		continue
con.commit()
