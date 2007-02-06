all:
	echo 'Nothing to build.'

webadv:
	mkdir -p advisories/
	aerrate/aerrate.py -r --source=site --type=all --release=enterprise

socksadv:
	mkdir -p advisories/
	http_proxy="" https_proxy="" dsocksify aerrate/aerrate.py -r --source=site --type=all --release=enterprise

rhnadv:
	mkdir -p advisories.rhn/
#	lftp http://66.187.229.33/errata/ -e 'mget http://66.187.229.33/errata/*.xml'
	wget -c -r -l1 -nd -np -P advisories.rhn http://66.187.229.33/errata/

clean:
	rm -rf advisories/
