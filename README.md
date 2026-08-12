<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" alt="SPID" data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" width="500" height="98" />

[![Join the #spid-php channel](https://img.shields.io/badge/Slack%20channel-%23spid--php-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/CB6DCK274)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid)
[![Build Status](https://travis-ci.org/italia/spid-php-lib.svg?branch=master)](https://travis-ci.org/italia/spid-php-lib)

>  **CURRENT VERSION: v0.35**

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

- [spid-php-lib](#spid-php-lib)
- [Table of Contents](#table-of-contents)
  - [Repository layout](#repository-layout)
  - [Getting Started](#getting-started)
    - [PHP compatibility](#php-compatibility)
    - [Prerequisites](#prerequisites)
    - [Configuring and Installing](#configuring-and-installing)
    - [Usage](#usage)
      - [Performing login](#performing-login)
      - [Performing logout](#performing-logout)
      - [Complete API](#complete-api)
    - [Example](#example)
      - [Demo application](#demo-application)
  - [Features](#features)
    - [More features](#more-features)
  - [Troubleshooting](#troubleshooting)
  - [Testing](#testing)
    - [Unit tests](#unit-tests)
    - [Linting](#linting)
  - [Contributing](#contributing)
  - [See also](#see-also)
  - [Authors](#authors)
  - [License](#license)


## Repository layout

* [bin/](bin/) auxiliary scripts
* [example/](example/) contains a demo application
* [src/](src/) contains the library implementation
* [test/](test/) contains the unit tests

## Getting Started

### PHP compatibility

The constraint declared in [composer.json](composer.json) is `"php": "^7.4 || ^8.0"`, that is
PHP 7.4 and every 8.x release. The table below reports what has actually been verified by
running the whole CI pipeline (`composer validate --strict`, `composer install`,
`phpcs --standard=PSR2`, `phpunit`) on each release, against the production IdP metadata
downloaded from the SPID registry. End-of-life dates are the ones published on
[php.net/supported-versions](https://www.php.net/supported-versions.php) and
[php.net/eol](https://www.php.net/eol.php).

| PHP | Security support until | Upstream status | `composer install` | Library code | Test suite | In the CI matrix |
|:---|:---|:---|:---|:---|:---|:---|
| 7.4 | 28 Nov 2022 | end of life | yes | works | passes | yes |
| 8.0 | 26 Nov 2023 | end of life | yes | works | passes | yes |
| 8.1 | 31 Dec 2025 | end of life | yes | works | passes | yes |
| 8.2 | 31 Dec 2026 | security fixes only | yes | works | passes | yes |
| 8.3 | 31 Dec 2027 | security fixes only | yes | works | passes | yes |
| 8.4 | 31 Dec 2028 | active support | yes | works | passes | yes |
| 8.5 | 31 Dec 2029 | active support | yes | works | passes | yes |

Notes:

* PHP 7.4, 8.0 and 8.1 have reached end of life upstream and receive no security fixes. They are
  kept in the matrix for backward compatibility only: new deployments should target PHP 8.4 or 8.5.
* No deprecation notice is emitted by the library on any of these releases. In particular every
  implicitly nullable parameter (`Type $x = null`, deprecated since 8.4 and an error in PHP 9.0)
  has been made explicit.

### Prerequisites

```sh
sudo apt install composer make openssl php-curl php-zip php-xml
```

### Configuring and Installing


**NOTE**: during testing, please use the test Identity Provider [spid-testenv2](https://github.com/italia/spid-testenv2).


1. Install with composer 

    ```composer require italia/spid-php-lib```

2. (**OPTIONAL**) Manually generate key and certificate files for your Service Provider (SP).

    Example: 
    ```openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Milan/O=myservice/CN=localhost" -keyout sp.key -out sp.crt```

   This step can be skipped: the library takes care of this step automatically if you declare the optional `sp_key_cert_values` key in the `settings` array. Check the example in the [Usage](#usage) section for further details.

3. Download the Identity Provider (IdP) metadata files and place them in a directory in your project, for example `idp_metadata`. 
    A convenience tool is provided to download those of the production IdPs: [vendor/italia/spid-php-lib/bin/download_idp_metadata.php](bin/download_idp_metadata.php), example usage:
    ```sh
    mkdir idp_metadata
    php vendor/italia/spid-php-lib/bin/download_idp_metadata.php ./idp_metadata
    ```

    **How the tool gets the metadata, and what that means for you.** The SPID registry used to
    publish, for every IdP, the URL of the metadata document the IdP itself signs and serves; the
    tool downloaded that document verbatim. That endpoint is gone, and the registry no longer
    exposes a per-IdP metadata URL: it returns the entityID, the SSO/SLO endpoints and the signing
    certificates as JSON. The tool now rebuilds the metadata from that payload, which means the
    files it writes are **not signed** and are trusted on the strength of the TLS connection to
    `registry.spid.gov.it` alone. This library never verified the metadata signature anyway, so its
    own behaviour is unchanged — but if your deployment or your compliance process verifies the
    stored metadata against the AgID trust anchor, that check is no longer possible on these files
    and you should keep fetching each IdP's own document instead.

    The tool also writes only the signing certificates that are currently valid: the registry lists
    expired ones too, sometimes first, and this library reads only the first certificate of the
    document. Re-run the tool when a certificate is about to expire; it warns on stderr about any
    file in the destination directory that it did not write, which is what you get for an IdP that
    has left the registry, and for the files of an older version of the tool, whose naming scheme
    followed the old registry payload.

    *TEST ENVIRONMENT: If you are using [spid-testenv2](https://github.com/italia/spid-testenv2), manually download the IdP metadata and place it in your `idp_metadata` folder*

4. Make your SP known to IdPs: for production follow the guidelines at [https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid](https://www.spid.gov.it/come-diventare-fornitore-di-servizi-pubblici-e-privati-con-spid)

    *TEST ENVIRONMENT: simply download your Service Provider (SP) metadata and place it in the appropriate folder of the [test environment](https://github.com/italia/spid-testenv2). The test environment must be restarted after every change to the SP metadata.*



### Usage

All classes provided by this package reside in the `Italia\Spid` namespace.
More detailed documentation is available in the [SAMLInterface.php](/src/Spid/Interfaces/SAMLInterface.php) file.

Load them using the composer-generated autoloader:
```php
require_once(__DIR__ . "/vendor/autoload.php");
```

The main class is `Italia\Spid\Sp` (service provider).

Generate a settings array following this guideline

```php
$settings = array(
    'sp_entityid' => SP_BASE_URL, // preferred: https protocol, no trailing slash, example: https://sp.example.com/
    'sp_key_file' => '/path/to/sp.key',
    'sp_cert_file' => '/path/to/sp.crt',
    'sp_comparison' => 'exact', // one of: "exact", "minimum", "better" or "maximum"
    'sp_assertionconsumerservice' => [
        // order is important ! the 0-base index in this array will be used as ID in the calls
        SP_BASE_URL . '/acs',
        ...
    ],
    'sp_singlelogoutservice' => [
        // order is important ! the 0-base index in this array will be used as ID in the calls
        [SP_BASE_URL . '/slo', 'POST'],
        [SP_BASE_URL . '/slo', 'REDIRECT']
        ...
    ],
    'sp_org_name' => 'your organization full name',
    'sp_org_display_name' => 'your organization display name',
    'sp_key_cert_values' => [ // Optional: remove this if you want to generate .key & .crt files manually
        'countryName' => 'Your Country',
        'stateOrProvinceName' => 'Your Province or State',
        'localityName' => 'Locality',
        'commonName' => 'Name',
        'emailAddress' => 'your@email.com',
    ]
    'idp_metadata_folder' => '/path/to/idp_metadata/',
    'sp_attributeconsumingservice' => [
        // order is important ! the 0-base index in this array will be used as ID in the calls
        ["fiscalNumber"],
        ["name", "familyName", "fiscalNumber", "email", "spidCode"],
        ...
    ],
    // Time in seconds of skew that is acceptable between client and server when checking OnBefore and NotOnOrAfter
    // assertion condition validity timestamps, and IssueInstant response / assertion timestamps. Optional.
    // Default is 0. Acceptable range: 0-300 (inclusive)
    'accepted_clock_skew_seconds' => 100
);
```

then initialize the main Sp class

```php
$sp = new Italia\Spid\Sp($settings);
```

>*Don't want the library to generate .key and .crt files for you? Then remove the `sp_key_cert_values` key from the `settings` array, or decalre* 

```php
// $autoconfiguration skips .key/.crt generation if set to false
$sp = new Italia\Spid\Sp($settings, null, $autoconfiguration = false);
```

#### Performing login


```php
// shortname of IdP, same as the name of corresponding IdP metadata file, without .xml
$idpName = 'testenv';
// index of assertion consumer service as per the SP metadata (sp_assertionconsumerservice in settings array)
$assertId = 0;
// index of attribute consuming service as per the SP metadata (sp_attributeconsumingservice in settings array)
$attrId = 1;

// Generate the login URL and redirect to the IdP login page
$sp->login($idpName, $assertId, $attrId);
```
Complete the login operation by calling
```php
$sp->isAuthenticated();
```
at the assertion consumer service URL. 

Then call
```php
$userAttributes = $sp->getAttributes();
```
to receive an array of the requested user attributes.

#### Performing logout

Call
```php
// index of single logout service as per the SP metadata (sp_singlelogoutservice in settings array)
$sloId = 0;

$sp->logout($sloId);
```
The method will redirect to the IdP Single Logout page, or return false if you are not logged in.

#### Complete API

|**Method**|**Description**|
|:---|:---|
|\__contruct($settings, $protocol = null, $autoconfigure = true)|`$settings` should be based on the example provided in the [Usage](#usage) section. `$protocol` represents the protocol used for login. At the moment only `SAML` is supported, and can be selected by either `$protocol = 'saml'` or the default `$protocol = null`. `$autoconfigure` tells the constructor if it should check for .key and .crt files at the specified location from the `$settings` array and generate them in case they are not found. Set this to `false` if you wish to generate those manually.|
|loadIdpFromFile(string $filename)|loads an `Idp` object by parsing the provided XML at `$filename`|
|getIdpList() : array|loads all the `Idp` objects from the `idp_metadata_folder` provided in settings|
|getIdp(string $filename)|alias of `loadIdpFromFile`|
|getSPMetadata() : string|returns the SP metadata as a string|
|login(string $idpFilename, int $assertID, int $attrID, $level = 1, string $redirectTo = null, $shouldRedirect = true)|login with REDIRECT binding. Use `$idpFilename` to select in IdP for login by indicating the name (without extension) of an XML file in your `idp_metadata_folder`. `$assertID` and `$attrID` indicate respectively the array index of `sp_assertionconsumerservice` and `sp_attributeconsumingservice` provided in settings. Optional parameters: `$level` for SPID authentication level (1, 2 or 3), `$redirectTo` to indicate an url to redirect to after login, `$shouldRedirect` to indicate if the login function should automatically redirect to the IdP or should return the login url as a string|
|loginPost(string $idpName, int $ass, int $attr, $level = 1, string $redirectTo = null, $shouldRedirect = true)|like login, but uses POST binding|
|logout(int $slo, string $redirectTo = null, $shouldRedirect = true)|logout with REDIRECT binding. `$slo` indicates the array index of the `sp_singlelogoutservice` provided in settings. Optional parameters: `$redirectTo` to indicate an url to redirect to after login, `$shouldRedirect` to indicate if the login function should automatically redirect to the IdP or should return the login url as a string|
|logoutPost(int $slo, string $redirectTo = null, $shouldRedirect = true)|like logout, but uses POST binding|
|isAuthenticated() : bool|checks if the user is authenticated. This method **MUST** be called after login and logout to finalize the operation.|
|getAttributes() : array|If you requested attributes with an attribute consuming service during login, this method will return them in array format|

### Example

A basic demo application is provided in the [example/](example/) directory of this repository.

**/example and /tests folders are NOT provided with the production version from packagist, remember to require the `dev-develop` version or just clone this repository (advised)**

To try it out:

1. Generate a test certificate and key pair with:

   ```sh
   openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -subj "/C=IT/ST=Italy/L=Milan/O=myservice/CN=localhost" -keyout sp.key -out sp.crt
   ```

2. Adapt the hostname of the SP changing the `$base` variable in the `example/index.php` file; the browser you'll be testing from must be able to resolve the FQDN (the default is `https://sp.example.com`). Using HTTPS is strongly suggested.

3. Configure and install the test IdP [spid-testenv2](https://github.com/italia/spid-testenv2)

4. Serve the `example` dir from your preferred webserver

5. Visit https://sp.example.com/metadata to get the SP metadata, then copy these over to the IdP and register the SP with the IdP

6. Visit https://idp.example.com/metadata to get the IdP metadata, then save it as `example/idp_metadata/testenv.xml` to register the IdP with the SP

7. Visit: https://sp.example.com and click `login`.

#### Demo application

A Docker-based demo application is available at [https://github.com/simevo/spid-php-lib-example](https://github.com/simevo/spid-php-lib-example).

## Features

- provides a **lean implementation** without relying on external SAML packages
- **routing-agnostic**, can be integrated in any web framework / CMS
- uses a **session** to store the authentication result and the received attributes
- does not currently support Attribute Authority (AA)

|<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-c-lb.png?raw=true" width="100" /><br />_Compliance with [SPID regulations](http://www.agid.gov.it/sites/default/files/circolari/spid-regole_tecniche_v1.pdf) (for Service Providers)_||
|:---|:---|
|**Metadata:**||
|parsing of IdP XML metadata (1.2.2.4)|✓|
|support for multiple signing certificates in IdP XML metadata (1.2.2.4)||
|parsing of AA XML metadata (2.2.4)||
|SP XML metadata generation (1.3.2)|✓|
|**AuthnRequest generation (1.2.2.1):**||
|generation of AuthnRequest XML|✓|
|HTTP-Redirect binding|✓|
|HTTP-POST binding|✓|
|`AssertionConsumerServiceURL` customization|The library uses `AssertionConsumerServiceIndex` customization which is preferred|
|`AssertionConsumerServiceIndex` customization|✓|
|`AttributeConsumingServiceIndex` customization|✓|
|`AuthnContextClassRef` (SPID level) customization|✓|
|`RequestedAuthnContext/@Comparison` customization|✓|
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

* [x] Generation of SPID button markup

## Security requirements for integrators

Some of the security properties of a SPID login depend on the application around
this library, not only on the library itself.

- **Select the Identity Provider by name, from a server-side list.** `login()` and
  `loginPost()` take the identifier of an IdP whose metadata is in
  `idp_metadata_folder`; the certificate in that metadata is the trust anchor used
  to validate the Response. The library resolves the identifier inside the
  configured folder and refuses paths, URLs and stream wrappers, but the
  application should still validate the value against `getIdpList()` before passing
  it on, as `example/views/login.php` does. Never pass a request parameter straight
  to `login()`.
- **Keep the metadata folder trustworthy.** Every `*.xml` in it is a trust anchor.
  Only the IdP metadata your deployment has verified belongs there, and the
  directory should not be writable by the web server. `bin/download_idp_metadata.php`
  refreshes it from the SPID registry.
- **Configure PHP sessions properly.** The library regenerates the session id when
  the login completes, but the surrounding settings are the application's:
  `session.use_strict_mode=1` and `session.use_only_cookies=1`, cookies marked
  `Secure` and `HttpOnly` with an explicit `SameSite`, and HTTPS throughout.
- **Check the level you get.** The level asserted by the IdP is validated against
  the one requested in the AuthnRequest, following
  `RequestedAuthnContext/@Comparison` (`sp_comparison`, `exact` by default). Read
  `getAttributes()` and the session level rather than assuming the requested level
  was honoured.
- **Keep the dependencies current.** `robrichards/xmlseclibs` must be at least
  3.1.5. Update `composer.lock` too, not just `composer.json`, and run
  `composer audit` as part of your release.

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

To test and lint this package you must place yourself in its root directory, then follow the provided instructions.

Assuming you followed the installation instructions with composer, simply do:

```sh
cd vendor/italia/spid-php-lib
```

### Unit tests

Install the prerequisites with composer:
```sh
composer install
```

then launch the unit tests with PHPunit:
```sh
./vendor/bin/phpunit --stderr --testdox tests
```

The suite runs against the IdP metadata committed under
[tests/fixtures/idp_metadata/](tests/fixtures/idp_metadata/), so it needs no network access and its
result does not depend on the SPID registry being reachable. To exercise the registry itself, run
the downloader by hand:
```sh
bin/download_idp_metadata.php example/idp_metadata
```
which is what the nightly `registry-smoke` CI job does.

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

Copyright (c) 2018-2020, Developers Italia

License: BSD 3-Clause, see [LICENSE](LICENSE) file.
