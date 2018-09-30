<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" alt="SPID" data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" width="500" height="98" />

[![Join the #spid-perl channel](https://img.shields.io/badge/Slack%20channel-%23spid--perl-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/C7ESTMQDQ)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid)
[![Build Status](https://travis-ci.org/italia/spid-php-lib.svg?branch=master)](https://travis-ci.org/italia/spid-php-lib)

> ⚠️ **WORK IN PROGRESS (but should be useable)** ⚠️

# spid-php-lib
PHP package for SPID authentication.

This PHP package is aimed at implementing SPID **Service Providers**. [SPID](https://www.spid.gov.it/) is the Italian digital identity system, which enables citizens to access all public services with a single set of credentials. This package provides a layer of abstraction over the SAML protocol by exposing just the subset required in order to implement SPID authentication in a web application.

Features:
- provides a **lean implementation** without relying on external SAML packages
- **routing-agnostic**, can be integrated in any web framework / CMS
- uses a **session** to store the authentication result and the received attributes
- does not currently support Attribute Authority (AA).

Alternatives for PHP:
- [spid-php](https://github.com/italia/spid-php) based on [SimpleSAMLphp](https://simplesamlphp.org/)
- [spid-php2](https://github.com/simevo/spid-php2) based on [php-saml](https://github.com/onelogin/php-saml)

Alternatives for other languages:
- [spid-perl](https://github.com/italia/spid-perl)
- [spid-ruby](https://github.com/italia/spid-ruby)

## Repository layout

* [bin/](bin/) auxiliary scripts
* [example/](example/) will contain a demo application
* [src/](src/) will contain the implementation
* [test/](test/) will contain the unit tests

## Getting Started

Tested on: amd64 Debian 9.5 (stretch, current stable) with PHP 7.0.

Supports PHP 7.0, 7.1 and 7.2.

### Prerequisites

```sh
sudo apt install composer make openssl php-curl php-zip php-xml phpunit
```

### Configuring and Installing

Before using this package, you must:

1. Install prerequisites with composer:
```sh
composer install --no-dev
```

2. (Optionally) edit the `example/.env` file; the default value `localhost` for the hostnames of the SP and IdP is OK for local tests; if you change that, check that the FQDNs resolve. This can be achieved by adding a directive in `/etc/hosts` or equivalent.

3. Download and verify the Identity Provider (IdP) metadata files; it is advised to place them in a separate [idp_metadata/](example/idp_metadata/) directory. A convenience tool is provided for this purpose: [bin/download_idp_metadata.php](bin/download_idp_metadata.php), example usage:
```sh
bin/download_idp_metadata.php ./example/idp_metadata
```

4. Generate key and certificate for the Service Provider (SP).

5. Reciprocally configure the SP and the IdPs to talk to each other by exchanging their metadata.

**NOTE**: during testing, it is highly adviced to use the test Identity Provider [spid-testenv2](https://github.com/italia/spid-testenv2).

### Usage

All classes provided by this package reside in the `Italia\Spid` namespace.

Load them using the composer-generated autoloader:
```php
require_once(__DIR__ . "/../vendor/autoload.php");
```

The main class is `Italia\Spid\Sp` (service provider), sample instantiation:

```php
$settings = array(
    'sp_entityid' => 'https://example.com/myservice',
    'idp_metadata_folder' => './idp_metadata/',
    ...
);
$sp = new Italia\Spid\Sp($settings);
```

By default the the service provider loads all IdP metadata found in the specified `idp_metadata_folder` and is ready for use, as in:

```php
// shortname of IdP, same as the name of corresponding IdP metadata file, without .xml
$idpName = 'testenv';
// return url
$returnTo = 'https://example.com/return_to_url';
// index of assertion consumer service as per the SP metadata
$assertId = 0;
// index of attribute consuming service as per the SP metadata
$attrId = 1;
// SPID level (1, 2 or 3)
$spidLevel = 1;
$sp->login($idpName, $assertId, $attrId, $redirectTo, $spidLevel);
...
$attributes = $sp->getAttributes();
var_dump($attributes);
$sp->logout();
```

### Example

A basic demo application is provided in the [example/](example/) directory.

To try it out you have two options: either manually or with the supplied [docker-compose](https://docs.docker.com/compose/overview/) file.

In either case, this screencast shows what you should see if all goes well:

![img](images/screencast.gif)

#### Manual install

1. Configure and install this package (see above)

2. Configure and install the test Identity Provider [spid-testenv2](https://github.com/italia/spid-testenv2)

3. Serve the `example` dir from your preferred webserver

4. Visit https://sp.example.com/metadata.php to get the SP metadata, then copy these over to the IdP and register the SP

5. Visit https://idp.example.com/metadata to get the IdP metadata, then save it as `example/idp_metadata/idp_testenv2.xml` to register the IdP with the SP

6. Visit: https://sp.example.com and click `login`.

#### Using docker-compose

The supplied [example/docker-compose.yml](example/docker-compose.yml) file defines and runs a multi-container Docker application that comprises this example and the test Identity Provider [spid-testenv2](https://github.com/italia/spid-testenv2), configured to talk to each other.
 
To use it, in the `example` directory:

1. (Optionally) edit the `.env` file

2. Run `make` (this creates the needed certificates and configurations)

3. Run `docker-compose up --build`

4. Run `make post` (this exchanges the metadata between SP and test IdP)

5. Visit: http://localhost:8099/ and click `login`.

## Troubleshooting

It is advised to install a browser plugin to trace SAML messages:

- Firefox:

  - [SAML-tracer by Olav Morken, Jaime Perez](https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/)
  - [SAML Message Decoder by Magnus Suther](https://addons.mozilla.org/en-US/firefox/addon/saml-message-decoder-extension/)

- Chrome/Chromium:

  - [SAML Message Decoder by Magnus Suther](https://chrome.google.com/webstore/detail/saml-message-decoder/mpabchoaimgbdbbjjieoaeiibojelbhm)
  - [SAML Chrome Panel by MLai](https://chrome.google.com/webstore/detail/saml-chrome-panel/paijfdbeoenhembfhkhllainmocckace)
  - [SAML DevTools extension by stefan.rasmusson.as](https://chrome.google.com/webstore/detail/saml-devtools-extension/jndllhgbinhiiddokbeoeepbppdnhhio)

In addition, you can use the [SAML Developer Tools](https://www.samltool.com/online_tools.php) provided by onelogin to understand what is going on

## Testing

### Unit tests

Launch unit tests with PHPunit:
```
./vendor/bin/phpunit --stderr --testdox tests
```

### Linting

This project complies with the [PSR-2: Coding Style Guide](https://www.php-fig.org/psr/psr-2/).

Lint the code with:
```
./vendor/bin/phpcs --standard=PSR2 xxx.php
```

## SPID Compliance Assessment

|<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-c-lb.png?raw=true" width="100" /><br />_Compliance with [SPID regulations](http://www.agid.gov.it/sites/default/files/circolari/spid-regole_tecniche_v1.pdf) (for Service Providers)_||
|:---|:---|
|**Metadata:**||
|parsing of IdP XML metadata (1.2.2.4)|✓|
|parsing of AA XML metadata (2.2.4)||
|SP XML metadata generation (1.3.2)|✓|
|**AuthnRequest generation (1.2.2.1):**||
|generation of AuthnRequest XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|`AssertionConsumerServiceURL` customization|✓|
|`AssertionConsumerServiceIndex` customization|✓|
|`AttributeConsumingServiceIndex` customization|✓|
|`AuthnContextClassRef` (SPID level) customization|✓|
|`RequestedAuthnContext/@Comparison` customization||
|`RelayState` customization (1.2.2)|?|
|**Response/Assertion parsing**||
|verification of `Response/Signature` value (if any)|?|
|verification of `Response/Signature` certificate (if any) against IdP/AA metadata|?|
|verification of `Assertion/Signature` value|✓|
|verification of `Assertion/Signature` certificate against IdP/AA metadata|✓|
|verification of `SubjectConfirmationData/@Recipient`|?|
|verification of `SubjectConfirmationData/@NotOnOrAfter`|?|
|verification of `SubjectConfirmationData/@InResponseTo`|?|
|verification of `Issuer`|?|
|verification of `Destination`|?|
|verification of `Conditions/@NotBefore`|?|
|verification of `Conditions/@NotOnOrAfter`|?|
|verification of `Audience`|?|
|parsing of Response with no `Assertion` (authentication/query failure)|?|
|parsing of failure `StatusCode` (Requester/Responder)|?|
|verification of `RelayState` (saml-bindings-2.0-os 3.5.3)|?|
|**Response/Assertion parsing for SSO (1.2.1, 1.2.2.2, 1.3.1):**||
|parsing of `NameID`|✓|
|parsing of `AuthnContextClassRef` (SPID level)|✓|
|parsing of attributes|✓|
|**Response/Assertion parsing for attribute query (2.2.2.2, 2.3.1):**||
|parsing of attributes|✓|
|**LogoutRequest generation (for SP-initiated logout):**|✓|
|generation of LogoutRequest XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|**LogoutResponse parsing (for SP-initiated logout):**||
|parsing of LogoutResponse XML|✓|
|verification of `Response/Signature` value (if any)|✓|
|verification of `Response/Signature` certificate (if any) against IdP metadata|✓|
|verification of `Issuer`|✓|
|verification of `Destination`|✓|
|PartialLogout detection|?|
|**LogoutRequest parsing (for third-party-initiated logout):**||
|parsing of LogoutRequest XML|?|
|verification of `Response/Signature` value (if any)|?|
|verification of `Response/Signature` certificate (if any) against IdP metadata|?|
|verification of `Issuer`|?|
|verification of `Destination`|?|
|parsing of `NameID`|?|
|**LogoutResponse generation (for third-party-initiated logout):**||
|generation of LogoutResponse XML|?|
|HTTP-Redirect binding|?|
|HTTP-POST binding|?|
|PartialLogout customization|?|
|**AttributeQuery generation (2.2.2.1):**||
|generation of AttributeQuery XML|?|
|SOAP binding (client)|?|

## Contributing

For your contributions please use the [git-flow workflow](https://danielkummer.github.io/git-flow-cheatsheet/).

## See also

* [SPID page](https://developers.italia.it/it/spid) on Developers Italia

## Authors

Lorenzo Cattaneo and Paolo Greppi, simevo s.r.l.

## License

Copyright (c) 2018, Developers Italia

License: BSD 3-Clause, see [LICENSE](LICENSE) file.
