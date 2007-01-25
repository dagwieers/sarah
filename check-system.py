#!/usr/bin/python

import sys, os , re, sqlite
import rpm
import sarahlib

def vercmp((e1, v1, r1), (e2, v2, r2)):
        return rpm.labelCompare((e1, v1, r1), (e2, v2, r2))

sys.stdout = os.fdopen(1, 'w', 0)

hostname = sys.argv[1]

rpmqa = {}
for rpmfile in open('rpmqa-%s.txt' % hostname).readlines():
	rpmfile = rpmfile.rstrip()
	try:
		rec = re.search('(?P<name>[^/]+)-(?P<version>[\w\.]+)-(?P<release>[\w\.]+)\.(?P<arch>\w+)$', rpmfile).groupdict()
	except:
		try:
			rec = re.search('(?P<name>[^/]+)-(?P<version>[\w\.]+)-(?P<release>[\w\.]+)$', rpmfile).groupdict()
		except:
			rec = re.search('(?P<name>[^/]+)-(?P<version>[\w\.]+)-(?P<release>[\w\.]+)\.(?P<arch>\w+).rpm$', rpmfile).groupdict()
	rpmqa[rec['name']] = {'version': rec['version'], 'release': rec['release'], 'arch': rec['arch']}

	if rec['name'] == 'redhat-release':
		release = rec['version']
		arch = rec['arch']

con, cur = sarahlib.opendb()

upd = {}
adv = {}
cur.execute('select filename,rpm.advid,severity,synopsis from rpm,adv where prodshort == "%s" and arch == "%s" and rpm.advid == adv.advid and adv.type == "RHSA" order by rpm.advid' % (release, arch))
for rpmfile, advid, severity, synopsis in cur.fetchall():
	rec = re.search('(?P<name>[^/]+)-(?P<version>[\w\.]+)-(?P<release>[\w\.]+)\.(?P<arch>\w+).rpm$', rpmfile).groupdict()

	if rec['name'] in rpmqa.keys():
		ins = rpmqa[rec['name']]
		if vercmp(('0', rec['version'], rec['release']), ('0', ins['version'], ins['release'])) >= 0:
			if advid not in adv.keys():
				adv[advid] = {'severity': severity, 'synopsis': synopsis}

	if rec['name'] in upd.keys():
		sec = upd[rec['name']]
		if vercmp(('0', rec['version'], rec['release']), ('0', sec['version'], sec['release'])) >= 0:
			upd[rec['name']] = {'version': rec['version'], 'release': rec['release'], 'arch': rec['arch']}
	else:
		upd[rec['name']] = {'version': rec['version'], 'release': rec['release'], 'arch': rec['arch']}

#for rec in upd.keys():
#	print '%s: %s' % (rec, upd[rec])

print 'System %s is susceptible for the following advisories:' % hostname
for advid in adv.keys():
	print advid, adv[advid]['synopsis'], "(%s)" % adv[advid]['severity']
