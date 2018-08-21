all: example/sp.key

example/sp.key:
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout example/sp.key -out example/sp.crt

clean:
	rm -rf vendor
	rm -f example/sp.key
	rm -f example/sp.crt
	rm -f example/idp_metadata/*.xml
