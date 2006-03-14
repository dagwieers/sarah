#!/bin/bash

echo "Advisories with unknown severity:"
./sarahsql.py 'select advid,severity from adv where type = "RHSA" and severity = "unknown" order by advid'
echo

echo "Advisories with HTML and severity in synopsis:"
./sarahsql.py 'select advid,synopsis from adv where synopsis glob "*:*" order by advid'
echo

### FIXME: These do not work ?
#echo "Advisories with no rpms:"
#./sarahsql.py 'select a.advid, synopsis from adv a where ( select count(r.advid) from adv a, rpm r where r.advid = a.advid ) = 0.0'
#echo

#echo "Advisories with no refs:"
#./sarahsql.py 'select a.advid, synopsis from adv a where ( select count(*) from adv a, ref r where r.advid = a.advid ) = NULL'
#echo

echo -n "Number of advisories in adv: "
./sarahsql.py 'select distinct advid from adv' | wc -l
echo -n "Number of advisories in rpm: "
./sarahsql.py 'select distinct advid from rpm' | wc -l
echo -n "Number of advisories in ref: "
./sarahsql.py 'select distinct advid from ref' | wc -l
echo
