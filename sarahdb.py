#!/usr/bin/python

import sys, os, glob, sqlite
import sarahlib

import cElementTree as ElementTree

sys.stdout = os.fdopen(1, 'w', 0)

con, cur = sarahlib.opendb()
sarahlib.createtb(cur, 'adv')
sarahlib.createtb(cur, 'ref')
sarahlib.createtb(cur, 'rpm')
sarahlib.createtb(cur, 'pro')

filelist = glob.glob('advisories/RH?A-*.xml')
#filelist = glob.glob('advisories/RHSA-*.xml')
#filelist = ['advisories/RHSA-2005-791.xml', ]
filelist.sort()

for file in filelist:
	try:
		tree = ElementTree.ElementTree(file=file)
		root = tree.getroot()

		advrec = {};
		advrec['sender'] = root.get('from')
		advrec['version'] = root.get('version')
		advrec['version'] = root.get('version')

		advrec['advid'] = root.findtext('id')
		advrec['pushcount'] = root.findtext('pushcount')
		advrec['type'] = root.find('type').get('short')
		advrec['keywords'] = root.findtext('keywords')
		advrec['obsoletes'] = root.findtext('obsoletes')

		if root.find('group'):
			advrec['rhgroup'] = root.find('group').get('name')
		else:
			advrec['rhgroup'] = None

		### RHBAs and RHEAs do not have a severity level
		if advrec['type'] in ('RHBA', 'RHEA'):
			advrec['severity'] = None
		elif root.find('severity') != None:
			advrec['severity'] = root.find('severity').get('level')
		elif root.findtext('severity'):
			advrec['severity'] = root.findtext('severity')
		else:
#			raise Exception, 'severity not found.'
			advrec['severity'] = 'error'

		advrec['synopsis'] = root.findtext('synopsis')
		advrec['issued'] = root.find('issued').get('date')
		advrec['updated'] = root.find('updated').get('date')
		advrec['topic'] = root.findtext('topic')
		advrec['description'] = root.findtext('description')

#		print 'advrec:', advrec
		sarahlib.insertrec(cur, 'adv', advrec)

		for refnode in root.find('references'):
			refrec = { 'advid': advrec['advid'] }
			refrec['reftype'] = refnode.get('type')
			refrec['reference'] = refnode.get('href')

			if refrec['reftype'] == 'self':
				refrec['refid'] = advrec['advid']
			elif refnode.findtext('advisory'):
				refrec['refid'] = refnode.findtext('advisory')
			elif refnode.findtext('bugzilla'):
				refrec['refid'] = refnode.findtext('bugzilla')
			elif refnode.findtext('cve'):
				refrec['refid'] = refnode.findtext('cve')
			elif refnode.findtext('self'):
				refrec['refid'] = refnode.findtext('self')
			else:
				refrec['refid'] = 'error'
#				raise Exception, 'refid not found.'

			if refnode.find('summary'):
				refrec['summary'] = refnode.findtext('summary')
			else:
				refrec['summary'] = None

#			print 'refrec:', refrec
			sarahlib.insertrec(cur, 'ref', refrec)

		if not root.find('rpmlist'): continue
		for pronode in root.find('rpmlist'):
			prorec = { 'advid': advrec['advid'] }
			prorec['prodshort'] = pronode.get('short')
			prorec['product'] = pronode.findtext('name')
#			print prorec
			try: sarahlib.insertrec(cur, 'pro', prorec)
			except: pass

			if not pronode.find('file'): continue
			for rpmnode in pronode.findall('file'):
				rpmrec = { 'advid': advrec['advid'], 'prodshort': prorec['prodshort'] }
				rpmrec['arch'] = rpmnode.get('arch')
				rpmrec['filename'] = rpmnode.findtext('filename')
				if rpmnode.find('sum').get('type') == 'md5':
					rpmrec['md5'] = rpmnode.findtext('sum')
				rpmrec['channels'] = []
				for channel in root.findall('channel'):
					rpmrec['channels'].append(channel.get('name'))
#				print rpmrec
				sarahlib.insertrec(cur, 'rpm', rpmrec)
			
		print '\033[0;32m%s\033[0;0m' % os.path.basename(file).strip('.xml'),

	except Exception, e:
#	except (xml.sax._exceptions.SAXParseException, AttributeError, KeyError), e:
		print '\033[0;31m%s\033[0;0m' % os.path.basename(file),
		print e
#		raise
		continue
con.commit()
