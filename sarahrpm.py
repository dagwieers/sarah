#!/usr/bin/python

import sys

packagelist = None

try:
	import rpm
	ts = rpm.TransactionSet()
#	ts.setVSFlags(rpm.RPMVSF_NORSA | rpm.RPMVSF_NODSA)
	ts.setVSFlags(rpm._RPMVSF_NOSIGNATURES | rpm.RPMVSF_NOHDRCHK | rpm._RPMVSF_NODIGESTS | rpm.RPMVSF_NEEDPAYLOAD)
except:
	info(2, 'Disabling RPM capability since the rpm-python bindings could not be loaded.')
	cf.rpm = False
	ts = None

    mi = ts.dbMatch('basenames', filename)
    for h in mi:
        return h
    else:
        info(5, 'File %s not in rpmdb, including' % filename)

# vim:ts=4:sw=4
