#!/bin/bash

echo "Advisories with unknown severity:"
./sarahsql.py 'select advid,severity from adv where type = "RHSA" and severity = "unknown" order by advid'
echo

echo "Advisories with HTML and severity in synopsis:"
./sarahsql.py 'select advid,synopsis from adv where synopsis glob "*:*" order by advid'
echo

echo "RPMs with no prodshort:"
./sarahsql.py 'select a.advid from adv a, rpm r where a.advid = r.advid and r.prodshort = "None" order by a.advid'
echo

### FIXME: These do not work ?
#echo "Advisories with no rpms:"
#./sarahsql.py 'select a.advid, synopsis from adv a where ( select count(r.advid) from adv a, rpm r where r.advid = a.advid ) = 0.0'
#echo

#echo "Advisories with no refs:"
#./sarahsql.py 'select a.advid, synopsis from adv a where ( select count(*) from adv a, ref r where r.advid = a.advid ) = NULL'
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
