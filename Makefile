include .env

all:
  # Configure SP
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout example/sp.key -out example/sp.crt & wait;\
	envsubst < example/config.php.tpl > example/config.php
	composer install
  # Configure test IdP
	envsubst < example/spid-testenv2/config.yaml.tpl > example/spid-testenv2/config.yaml
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout example/spid-testenv2/idp.key -out example/spid-testenv2/idp.crt
	# Needed only to interact with production IdPs:
	#	./bin/download_idp_metadata.php example/idp_metadata

post:
	curl -o example/spid-testenv2/sp_metadata.xml http://localhost:8099/metadata
	curl -o example/idp_metadata/idp_testenv2.xml http://localhost:8088/metadata

clean:
	rm -rf vendor
	rm -f example/spid-testenv2/idp.key
	rm -f example/spid-testenv2/idp.crt
	rm -f example/spid-testenv2/sp_metadata.xml
	rm -f example/spid-testenv2/users.json
	rm -f example/sp.key
	rm -f example/sp.crt
	rm -f example/idp_metadata/*.xml
