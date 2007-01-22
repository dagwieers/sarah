#!/bin/bash

### This script checks a list of RHSA numbers against sarahdb

for RHSA in $*; do
	echo "RHSA $RHSA"
	echo "------------------"
        echo "Matches the following advisories:"
        ./sarahsql.py "select advid, severity, synopsis from adv where advid == '$RHSA'"
        echo
	echo "Providing the following updates:"
	./sarahsql.py "select distinct prodshort, filename, advid from rpm where advid == '$RHSA' and prodshort in ('3AS', '4AS') and arch == 'i386'"
	echo "------------------"
done
