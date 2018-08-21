<img src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" alt="SPID" data-canonical-src="https://github.com/italia/spid-graphics/blob/master/spid-logos/spid-logo-b-lb.png" width="500" height="98" />

[![Join the #spid-perl channel](https://img.shields.io/badge/Slack%20channel-%23spid--perl-blue.svg?logo=slack)](https://developersitalia.slack.com/messages/C7ESTMQDQ)
[![Get invited](https://slack.developers.italia.it/badge.svg)](https://slack.developers.italia.it/)
[![SPID on forum.italia.it](https://img.shields.io/badge/Forum-SPID-blue.svg)](https://forum.italia.it/c/spid)

> ⚠️ **WORK IN PROGRESS** ⚠️

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

### Prerequisites

```sh
sudo apt install composer make openssl php-curl php-zip php-xml phpunit
```

### Configuring and Installing

Before using this package, you must:

1. Install prerequisites with composer

2. Download and verify the Identity Provider (IdP) metadata files; it is advised to place them in a separate [idp_metadata/](example/idp_metadata/) directory. A convenience tool is provided for this purpose: [bin/download_idp_metadata.php](bin/download_idp_metadata.php).

3. Generate key and certificate for the Service Provider (SP).

All steps can be performed in an unattended fashion with:
```sh
composer install --no-dev
make
bin/download_idp_metadata.php
```

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

To use:

1. in `example/index.php`:

  - adapt the base url (`$base`) to your needs (use am IP address or a FQDN that is visible to the IdP)

2. in `example/login.php` change the IdP that will be used to login

3. Serve the `example` dir from your preferred webserver

4. visit https://sp.example.com/metadata.php to get the SP (Service Provider) metadata, then copy these over to the IdP and register the SP

5. visit: https://sp.example.com and click `login`.

This screencast shows what you should see if all goes well:

![img](images/screencast.gif)

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
phpunit --stderr --testdox tests
```

### Linting

This project complies with the [PSR-2: Coding Style Guide](https://www.php-fig.org/psr/psr-2/).

Lint the code with:
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
