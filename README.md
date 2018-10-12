<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" alt="SPID" data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" width="500" height="98" />

[![Join the #spid-php channel](https://img.shields.io/badge/Slack%20channel-%23spid--php-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/CB6DCK274)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid)
[![Build Status](https://travis-ci.org/italia/spid-php-lib.svg?branch=master)](https://travis-ci.org/italia/spid-php-lib)

>  **CURRENT VERSION: v0.20**

# spid-php-lib
PHP package for SPID authentication.

This PHP package is aimed at implementing SPID **Service Providers**. [SPID](https://www.spid.gov.it/) is the Italian digital identity system, which enables citizens to access all public services with a single set of credentials. This package provides a layer of abstraction over the SAML protocol by exposing just the subset required in order to implement SPID authentication in a web application.

Alternatives for PHP:
- [spid-php](https://github.com/italia/spid-php) based on [SimpleSAMLphp](https://simplesamlphp.org/)
- [spid-php2](https://github.com/simevo/spid-php2) based on [php-saml](https://github.com/onelogin/php-saml)

Framework specific libraries and examples based on spid-php-lib:
- [https://github.com/italia/spid-symfony-bundle](https://github.com/italia/spid-symfony-bundle)
- [https://github.com/simevo/spid-symfony3-example](https://github.com/simevo/spid-symfony3-example)
- [https://github.com/simevo/spid-wordpress](https://github.com/simevo/spid-wordpress)

Alternatives for other languages:
- [spid-perl](https://github.com/italia/spid-perl)
- [spid-ruby](https://github.com/italia/spid-ruby)



Table of Contents
=================

* [Repository layout](#repository-layout)
* [Getting started](#getting-started)
    * [Prerequisites](#prerequisites)
    * [Configuring & Installing](#configuring-and-installing)
    * [Usage](#usage)
        * [Performing login](#performing-login)
        * [Performing logout](#performing-logout)
        * [Complete API](#complete-api)
    * [Example](#example)
        * [Demo application](#demo-application)
* [Features](#features)
    * [More features](#more-features)
* [Troubleshooting](#troubleshooting)
* [Testing](#testing)
    * [Unit Tests](#unit-tests)
    * [Linting](#linting)
* [Contributing](#contributing)
* [See also](#see-also)
* [Authors](#authors)
* [License](#license)


## Repository layout

* [bin/](bin/) auxiliary scripts
* [example/](example/) contains a demo application
* [src/](src/) contains the library implementation
* [test/](test/) contains the unit tests

## Getting Started

Tested on: amd64 Debian 9.5 (stretch, current stable) with PHP 7.0.

Supports PHP 7.0, 7.1 and 7.2.

### Prerequisites

```sh
sudo apt install composer make openssl php-curl php-zip php-xml
```

### Configuring and Installing


**NOTE**: during testing, please use the test Identity Provider [spid-testenv2](https://github.com/italia/spid-testenv2).


1. Install with composer 
    
    ```composer require italia/spid-php-lib```

2. Generate key and certificate files for your Service Provider (SP).

    Example: 
    ```openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Milan/O=myservice/CN=localhost" -keyout sp.key -out sp.crt```

3. Download the Identity Provider (IdP) metadata files and place them in a directory in your project, for example `idp_metadata`. 
    A convenience tool is provided to download those of the production IdPs: [vendor/italia/spid-php-lib/bin/download_idp_metadata.php](bin/download_idp_metadata.php), example usage:
    ```sh
    mkdir idp_metadata
    php vendor/italia/spid-php-lib/bin/download_idp_metadata.php ./idp_metadata
    ```
    
    *TEST ENVIRONMENT: If you are using [spid-testenv2](https://github.com/italia/spid-testenv2), manually download the IDP metadata and place it in your `idp_metadata` folder*

4. Make your SP known to IDPs: for production follow the guidelines at [https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid](https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid)

    *TEST ENVIRONMENT: simply download your Service Provider (SP) metadata and place it in the appropriate folder of the [test environment](https://github.com/italia/spid-testenv2). The test environment must be restarted after every change to the SP metadata.*



### Usage

All classes provided by this package reside in the `Italia\Spid` namespace.

Load them using the composer-generated autoloader:
```php
require_once(__DIR__ . "/../vendor/autoload.php");
```

The main class is `Italia\Spid\Sp` (service provider).
Generate a settings array following this guideline

```php
$settings = array(
    'sp_entityid' => SP_BASE_URL, // Example: https://sp.example.com/
    'sp_key_file' => '/path/to/sp.key',
    'sp_cert_file' => '/path/to/sp.crt',
    'sp_assertionconsumerservice' => [
        SP_BASE_URL . '/acs'
    ],
    'sp_singlelogoutservice' => [
        [SP_BASE_URL . '/slo', 'POST'],
        [SP_BASE_URL . '/slo', 'REDIRECT']
        ...
    ],
    'sp_org_name' => 'YOUR_ORGANIZATION',
    'sp_org_display_name' => 'YOUR_ORGANIZATION',
    'idp_metadata_folder' => '/path/to/idp_metadata/',
    'sp_attributeconsumingservice' => [
        ["name", "familyName", "fiscalNumber", "email", "spidCode"]
        ...
    ]
);
```

then initialise the main Sp class

```
$sp = new Italia\Spid\Sp($settings);
```

#### Performing login


```php
// shortname of IdP, same as the name of corresponding IdP metadata file, without .xml
$idpName = 'testenv';
// index of assertion consumer service as per the SP metadata (sp_assertionconsumerservice in settings array)
$assertId = 0;
// index of attribute consuming service as per the SP metadata (sp_attributeconsumingservice in settings array)
$attrId = 1;

// Generate the login URL and redirect to the IDP login page
$sp->login($idpName, $assertId, $attrId);
```
Complete the login operation by calling
```
$sp->isAuthenticated();
```
at the assertion consumer service URL. 

Then call
```
$userAttributes = $sp->getAttributes();
```
to receive an array of the requested user attributes.

#### Performing logout

Call
```
// index of single logout service as per the SP metadata (sp_singlelogoutservice in settings array)
$sloId = 0;

$sp->logout($sloId);
```
The method will redirect to the IDP Single Logout page, or return false if you are not logged in.

#### Complete API

|**Method**|**Description**|
|:---|:---|
|loadIdpFromFile(string $filename)|loads an `Idp` object by parsing the provided XML at `$filename`|
|getIdpList() : array|loads all the `Idp` objects from the `idp_metadata_folder` provided in settings|
|getIdp(string $filename)|alias of `loadIdpFromFile`|
|getSPMetadata() : string|returns the SP metadata as a string|
|login(string $idpFilename, int $assertID, int $attrID, $level = 1, string $redirectTo = null, $shouldRedirect = true)|login with REDIRECT binding. Use `$idpFilename` to select in IDP for login by indicating the name (without extension) of an XML file in your `idp_metadata_folder`. `$assertID` and `$attrID` indicate respectively the array index of `sp_assertionconsumerservice` and `sp_attributeconsumingservice` provided in settings. Optional parameters: `$level` for SPID authentication level (1, 2 or 3), `$redirectTo` to indicate an url to redirect to after login, `$shouldRedirect` to indicate if the login function should automatically redirect to the IDP or should return the login url as a string|
|loginPost(string $idpName, int $ass, int $attr, $level = 1, string $redirectTo = null, $shouldRedirect = true)|like login, but uses POST binding|
|public function logout(int $slo, string $redirectTo = null, $shouldRedirect = true)|`$slo` indicates the array index of the `sp_singlelogoutservice` provided in settings. Optional parameters: `$redirectTo` to indicate an url to redirect to after login, `$shouldRedirect` to indicate if the login function should automatically redirect to the IDP or should return the login url as a string|
|logoutPost(int $slo, string $redirectTo = null, $shouldRedirect = true)|like logout, but uses POST binding|
|isAuthenticated() : bool|checks if the user is authenticated. This method **MUST** be caled after login and logout to finalise the operation.|
|getAttributes() : array|If you requested attributes with an attribute consuming service during login, this method will return them in array format|

### Example

A basic demo application is provided in the [example/](example/) directory of this repository.

**/example and /tests folders are NOT provided with the production version, remember to require dev-development version with composer**


To try it out:

1. Configure and install this package using the development version

    ```
   composer require italia/spid-php-lib:dev-develop
   ```
   
   or download the archived version directly from GitHub.
   
   Then generate a test certificate and key pair with:
   
   ```
   openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Milan/O=myservice/CN=localhost" -keyout sp.key -out sp.crt & wait;\
   ```
   
2. Adapt the hostname of the SP changing the `$base` variable in the `example/index.php` file; the browser you'll be testing from must be able to resolve the FQDN (the default is `https://sp.example.com`). Using HTTPS is strongly suggested.

3. Configure and install the test IdP [spid-testenv2](https://github.com/italia/spid-testenv2)

4. Serve the `example` dir from your preferred webserver

5. Visit https://sp.example.com/metadata to get the SP metadata, then copy these over to the IdP and register the SP with the IdP

6. Visit https://idp.example.com/metadata to get the IdP metadata, then save it as `example/idp_metadata/testenv.xml` to register the IdP with the SP

7. Visit: https://sp.example.com and click `login`.

#### Demo application
A Docker based demo application is available at [https://github.com/simevo/spid-php-lib-example](https://github.com/simevo/spid-php-lib-example)

## Features

- provides a **lean implementation** without relying on external SAML packages
- **routing-agnostic**, can be integrated in any web framework / CMS
- uses a **session** to store the authentication result and the received attributes
- does not currently support Attribute Authority (AA)

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
|`AssertionConsumerServiceURL` customization|The library uses `AssertionConsumerServiceIndex` customizaton which is preferred|
|`AssertionConsumerServiceIndex` customization|✓|
|`AttributeConsumingServiceIndex` customization|✓|
|`AuthnContextClassRef` (SPID level) customization|✓|
|`RequestedAuthnContext/@Comparison` customization||
|`RelayState` customization (1.2.2)|✓|
|**Response/Assertion parsing**||
|verification of `Signature` value (if any)|✓|
|verification of `Signature` certificate (if any) against IdP/AA metadata|✓|
|verification of `Assertion/Signature` value|✓|
|verification of `Assertion/Signature` certificate against IdP/AA metadata|✓|
|verification of `SubjectConfirmationData/@Recipient`|✓|
|verification of `SubjectConfirmationData/@NotOnOrAfter`|✓|
|verification of `SubjectConfirmationData/@InResponseTo`|✓|
|verification of `Issuer`|✓|
|verification of `Assertion/Issuer`|✓|
|verification of `Destination`|✓|
|verification of `Conditions/@NotBefore`|✓|
|verification of `Conditions/@NotOnOrAfter`|✓|
|verification of `Audience`|✓|
|parsing of Response with no `Assertion` (authentication/query failure)|✓|
|parsing of failure `StatusCode` (Requester/Responder)|✓|
|**Response/Assertion parsing for SSO (1.2.1, 1.2.2.2, 1.3.1):**||
|parsing of `NameID`|✓|
|parsing of `AuthnContextClassRef` (SPID level)|✓|
|parsing of attributes|✓|
|**Response/Assertion parsing for attribute query (2.2.2.2, 2.3.1):**||
|parsing of attributes| |
|**LogoutRequest generation (for SP-initiated logout):**||
|generation of LogoutRequest XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|**LogoutResponse parsing (for SP-initiated logout):**||
|parsing of LogoutResponse XML|✓|
|verification of `Response/Signature` value (if any)|✓|
|verification of `Response/Signature` certificate (if any) against IdP metadata|✓|
|verification of `Issuer`|✓|
|verification of `Destination`|✓|
|PartialLogout detection|pending, see: [#46](https://github.com/italia/spid-php-lib/issues/46)|
|**LogoutRequest parsing (for third-party-initiated logout):**||
|parsing of LogoutRequest XML|✓|
|verification of `Response/Signature` value (if any)|✓|
|verification of `Response/Signature` certificate (if any) against IdP metadata|✓|
|verification of `Issuer`|✓|
|verification of `Destination`|✓|
|parsing of `NameID`|✓|
|**LogoutResponse generation (for third-party-initiated logout):**||
|generation of LogoutResponse XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|PartialLogout customization|pending, see: [#46](https://github.com/italia/spid-php-lib/issues/46)|
|**AttributeQuery generation (2.2.2.1):**||
|generation of AttributeQuery XML| |
|SOAP binding (client)| |

### More features

* [ ] Generation of SPID button markup


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

To configure and install the SP, follow the instructions provided in the [Example](#example) section.

Now move into the package directory to install dev dependencies
```
cd vendor/italia/spid-php-lib/
composer install
```

### Unit tests

Make sure you are in the package directory and run

```sh
./vendor/bin/phpunit --stderr --testdox tests
```

### Linting

This project complies with the [PSR-2: Coding Style Guide](https://www.php-fig.org/psr/psr-2/).

Make sure you are in the package directory, then lint the code with:

```
./vendor/bin/phpcs --standard=PSR2 xxx.php
```

## Contributing

For your contributions please use the [git-flow workflow](https://danielkummer.github.io/git-flow-cheatsheet/).

## See also

* [SPID page](https://developers.italia.it/it/spid) on Developers Italia

## Authors

Lorenzo Cattaneo and Paolo Greppi, simevo s.r.l.

## License

Copyright (c) 2018, Developers Italia

License: BSD 3-Clause, see [LICENSE](LICENSE) file.
