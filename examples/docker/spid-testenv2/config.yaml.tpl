---
base_url: "${IDP_ENTITYID}"
key_file: "./conf/idp.key"
cert_file: "./conf/idp.crt"
metadata:
  local:
  - "./conf/sp_metadata.xml"
debug: true
host: 0.0.0.0
port: 8088
https: false
endpoints:
  single_sign_on_service: "/sso"
  single_logout_service: "/slo"
