#!/bin/bash

### This script checks the consistency of the sarahdb
### Known problems with the RHSA content is listed per item

echo "Advisories with unknown severity:"
./sarahsql.py 'select advid,severity from adv where type = "RHSA" and severity = "unknown" order by advid'
echo

echo "Advisories with HTML and severity in synopsis:"
./sarahsql.py 'select advid,synopsis from adv where synopsis glob "*:*" order by advid'
echo

echo "RPMs with no prodshort:"
./sarahsql.py 'select adv.advid from adv, rpm where adv.advid = rpm.advid and rpm.prodshort = "None" order by adv.advid'
echo

### FIXME: These do not work ?
#echo "Advisories with no rpms:"
#./sarahsql.py 'select adv.advid, synopsis from adv where ( select count(rpm.advid) from adv, rpm where rpm.advid = adv.advid ) = 0.0'
#echo

#echo "Advisories with no refs:"
#./sarahsql.py 'select adv.advid, synopsis from adv where ( select count(*) from adv, ref where ref.advid = adv.advid ) = NULL'
#echo

#echo "Show non-unique filenames"
#echo "Show non-unique md5s"
#echo "Show non-unique refids"

echo -n "Number of advisories in adv: "
./sarahsql.py 'select distinct advid from adv' | wc -l
echo -n "Number of advisories in rpm: "
./sarahsql.py 'select distinct advid from rpm' | wc -l
echo -n "Number of advisories in ref: "
./sarahsql.py 'select distinct advid from ref' | wc -l
echo
