include .env

all:
#	#IDP certificates
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout example/spid-testenv2/idp.key -out example/spid-testenv2/idp.crt
#	#SP certificates
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout example/sp.key -out example/sp.crt & wait;\
	SP_CRT=`sed "s/^-*[A-Z].*-$///g" example/sp.crt | xargs` envsubst < example/spid-testenv2/sp_metadata.xml.tpl > example/spid-testenv2/sp_metadata.xml

	envsubst < example/spid-testenv2/config.yaml.tpl > example/spid-testenv2/config.yaml
	envsubst < example/config.php.tpl > example/config.php
	composer install
#	Needed only to interact with live IDPs
#	./bin/download_idp_metadata.php
clean:
	rm -rf vendor
	rm -f example/spid-testenv2/idp.key
	rm -f example/spid-testenv2/idp.crt
	rm -f example/sp.key
	rm -f example/sp.crt
	rm -f example/idp_metadata/*.xml
