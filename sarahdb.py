#!/usr/bin/python

import sys, os, glob, sqlite
import sarahlib

import cElementTree as ElementTree

sys.stdout = os.fdopen(1, 'w', 0)

def elattr(ro, at, fail=True):
	ret = ro.get(at)
	if not ret and fail:
		raise Exception, 'elattr: Attribute %s not found in element %s ' % (at, ro)
	return ret

def findel(ro, el, fail=True):
	ret = ro.findtext(el)
	if not ret and fail:
		raise Exception, 'findel: Element %s not found in root %s ' % (el, ro)
	return ret

def findelattr(ro, el, at, fail=True):
	try: 
		ret = root.find(el).get(at)
	except:
		if fail:
			raise Exception, 'findelattr: Element %s not found in root %s ' % (el, ro)
		return None
	if not ret and fail:
		raise Exception, 'findelattr: Attribute %s not found in element %s ' % (at, el)
	return ret

def find(ro, el, fail=False):
	ret = ro.find(el)
	if not ret:
		if fail:
			raise Exception, 'find: Element %s not found in root %s ' % (el, ro)
		return []
	return ret

def findall(ro, el, fail=False):
	ret = ro.findall(el)
	if not ret:
		if fail:
			raise Exception, 'findall: Element list %s not found in root %s ' % (el, ro)
		return []
	return ret

con, cur = sarahlib.opendb()
sarahlib.createtb(cur, 'adv')
sarahlib.createtb(cur, 'ref')
sarahlib.createtb(cur, 'rpm')
sarahlib.createtb(cur, 'pro')

filelist = glob.glob('advisories/RH?A-*.xml')
if filelist:
	print 'Using %s advisories from: ./advisories/' % len(filelist)
else:
	filelist = glob.glob('aerrate/advisories/RH?A-*.xml')
if filelist:
	print 'Using %s advisories from: ./advisories/' % len(filelist)
else:
	print >>sys.errout, 'error: No advisories found in ./advisories/ or ./aerrate/advisories/.'
	sys.exit(1)

#filelist = glob.glob('advisories/RHSA-*.xml')
#filelist = ['advisories/RHSA-2005-791.xml', ]
#filelist.sort()

for file in filelist:
	try:
		tree = ElementTree.ElementTree(file=file)
		root = tree.getroot()

		advrec = {};

		### FIXME: aerrate uses 'sender' instead of 'from' (unfixable)
		try: advrec['sender'] = elattr(root, 'from')
		except: advrec['sender'] = elattr(root, 'sender')

		advrec['version'] = elattr(root, 'version')

		advrec['advid'] = findel(root, 'id')
		advrec['pushcount'] = findel(root, 'pushcount')

		### FIXME: aerrate does not (always) add type short info, use filename (unverified)
#		try: advrec['type'] = findelattr(root, 'type', 'short')
#		except: advrec['type'] = file[0:4]
		advrec['type'] = findelattr(root, 'type', 'short')

		try: advrec['keywords'] = ' '.join(findel(root, 'keywords'))
		except: advrec['keywords'] = None
		try: advrec['obsoletes'] = ' '.join(findel(root, 'obsoletes'))
		except: advrec['obsoletes'] = None

		advrec['rhgroup'] = findelattr(root, 'group', 'name', fail=False)

		if advrec['type'] in ('RHBA', 'RHEA'):
			advrec['severity'] = None
		else:
			### FIXME: aerrate uses severity element text and not level attribute (patched)
#			try: advrec['severity'] = findelattr(root, 'severity', 'level')
#			except: advrec['severity'] = findel(root, 'severity')
			advrec['severity'] = findelattr(root, 'severity', 'level')

		advrec['synopsis'] = findel(root, 'synopsis')
		advrec['issued'] = findelattr(root, 'issued', 'date')
		advrec['updated'] = findelattr(root, 'updated', 'date')
		advrec['topic'] = findel(root, 'topic')

		### FIXME: aerrate should replace <p> by \n\n for better formatting or not replace at all
		advrec['description'] = findel(root, 'description')

#		print 'advrec:', advrec
		sarahlib.insertrec(cur, 'adv', advrec)

		for refnode in find(root, 'references'):
			refrec = { 'advid': advrec['advid'] }
			refrec['reftype'] = elattr(refnode, 'type')
			### FIXME: aerrate still implements the old format for reference information
			refrec['reference'] = elattr(refnode, 'href', fail=False)

			if refrec['reftype'] == 'self':
				refrec['refid'] = advrec['advid']
			elif refnode.findtext('advisory'):
				refrec['refid'] = findel(refnode, 'advisory')
			elif refnode.findtext('bugzilla'):
				refrec['refid'] = findel(refnode, 'bugzilla')
			elif refnode.findtext('cve'):
				refrec['refid'] = findel(refnode, 'cve')
			elif refnode.findtext('self'):
				refrec['refid'] = findel(refnode, 'self')
			else:
				refrec['refid'] = 'error'
#				raise Exception, 'refid not found.'

			refrec['summary'] = findel(refnode, 'summary', fail=False)

#			print 'refrec:', refrec
			sarahlib.insertrec(cur, 'ref', refrec)

		for pronode in find(root, 'rpmlist'):
			prorec = { 'advid': advrec['advid'] }
			### FIXME: aerrate does not (always) add product info, skip (unverified)
			prorec['prodshort'] = elattr(pronode, 'short', fail=False)
			prorec['product'] = findel(pronode, 'name', fail=False)

#			print prorec
			try: sarahlib.insertrec(cur, 'pro', prorec)
			except: pass

			for rpmnode in findall(pronode, 'file'):
				rpmrec = { 'advid': advrec['advid'], 'prodshort': prorec['prodshort'] }
				rpmrec['arch'] = elattr(rpmnode, 'arch')
				rpmrec['filename'] = findel(rpmnode, 'filename')
				if rpmnode.find('sum').get('type') == 'md5':
					rpmrec['md5'] = findel(rpmnode, 'sum')
				rpmrec['channels'] = []
				for channel in findall(rpmnode, 'channel'):
					rpmrec['channels'].append(channel.get('name'))
#				print rpmrec
				sarahlib.insertrec(cur, 'rpm', rpmrec)
			
		print 'Processing: \033[0;32m%s\033[0;0m  \r' % os.path.basename(file).strip('.xml'),

	except Exception, e:
#	except (xml.sax._exceptions.SAXParseException, AttributeError, KeyError), e:
		print 'Error: \033[0;31m%s\033[0;0m' % os.path.basename(file),
		print e
#		raise
		continue
print 'Writing out sqlite database.\r'
con.commit()
