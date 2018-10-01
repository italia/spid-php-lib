all:
	# Configure SP
	openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Rome/O=myservice/CN=localhost" -keyout sp.key -out sp.crt & wait;\
	# Needed only to interact with the production IdPs:
	# ../bin/download_idp_metadata.php idp_metadata

clean:
	rm -f sp.key
	rm -f sp.crt
	rm -f idp_metadata/idp_*.xml
