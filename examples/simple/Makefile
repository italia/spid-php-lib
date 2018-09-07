include .env

all:
	# Configure SP
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout sp.key -out sp.crt & wait;\
	envsubst < config.php.tpl > config.php
	# Configure test IdP
	envsubst < spid-testenv2/config.yaml.tpl > spid-testenv2/config.yaml
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout spid-testenv2/idp.key -out spid-testenv2/idp.crt
	# Needed only to interact with the production IdPs:
	# ../bin/download_idp_metadata.php idp_metadata

post:
	curl -o spid-testenv2/sp_metadata.xml http://localhost:8099/metadata
	curl -o idp_metadata/idp_testenv2.xml http://localhost:8088/metadata

clean:
	rm -f spid-testenv2/idp.key
	rm -f spid-testenv2/idp.crt
	rm -f sp.key
	rm -f sp.crt
	rm -f idp_metadata/*.xml
