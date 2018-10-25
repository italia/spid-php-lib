<?php

namespace Italia\Spid\Spid\Saml;

class Settings
{
    const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    const REQUIRED = 1;
    const NOT_REQUIRED = 0;
    // Settings with value 1 are mandatory
    private static $validSettings = [
        'sp_entityid' => self::REQUIRED,
        'sp_key_file' => self::REQUIRED,
        'sp_cert_file' => self::REQUIRED,
        'sp_assertionconsumerservice' => self::REQUIRED,
        'sp_singlelogoutservice' => self::REQUIRED,
        'sp_attributeconsumingservice' => self::NOT_REQUIRED,
        'sp_org_name' => self::NOT_REQUIRED,
        'sp_org_display_name' => self::NOT_REQUIRED,
        'sp_key_cert_values' => [ 'required' => self::NOT_REQUIRED,
            'values' => [
                'countryName' => self::REQUIRED,
                'stateOrProvinceName' => self::REQUIRED,
                'localityName' => self::REQUIRED,
                'commonName' => self::REQUIRED,
                'emailAddress' => self::REQUIRED
            ]            
        ],
        'idp_metadata_folder' => self::REQUIRED
    ];

    private static $validAttributeFields = [
        "gender",
        "companyName",
        "registeredOffice",
        "fiscalNumber",
        "ivaCode",
        "idCard",
        "spidCode",
        "name",
        "familyName",
        "placeOfBirth",
        "countyOfBirth",
        "dateOfBirth",
        "mobilePhone",
        "email",
        "address",
        "expirationDate",
        "digitalAddress"
    ];

    public static function validateSettings(array $settings)
    {
        $missingSettings = array();
        $msg = 'Missing settings fields: ';
        array_walk(self::$validSettings, function ($v, $k) use (&$missingSettings, &$settings) {
            if (is_array($v) && $v['required'] == self::REQUIRED) {
                foreach ($v['values'] as $key => $value) {
                    if (
                        $value == self::REQUIRED &&
                        !array_key_exists($key, $settings[$k]['values'])
                    ) {
                        $missingSettings[$key] = 1;
                    }
                }
            } else if (self::$validSettings[$k] == self::REQUIRED && !array_key_exists($k, $settings)) {
                $missingSettings[$k] = 1;
            }
        });
        foreach ($missingSettings as $k => $v) {
            $msg .= $k . ', ';
        }
        if (count($missingSettings) > 0) {
            throw new \Exception($msg);
        }

        $invalidFields = array_diff_key($settings, self::$validSettings);
        $msg = 'Invalid settings fields: ';
        foreach ($invalidFields as $k => $v) {
            $msg .= $k . ', ';
        }
        if (count($invalidFields) > 0) {
            throw new \Exception($msg);
        }

        self::checkSettingsValues($settings);
    }

    public static function cleanOpenSsl($file, $isCert = false)
    {
        if ($isCert) {
            $k = $file;
        } else {
            if (!is_readable($file)) {
                throw new \Exception('File '.$file.' is not readable. Please check file permissions.');
            }
            $k = file_get_contents($file);
        }
        $ck = '';
        foreach (preg_split("/((\r?\n)|(\r\n?))/", $k) as $l) {
            if (strpos($l, '-----') === false) {
                $ck .= $l;
            }
        }
        return $ck;
    }

    private static function checkSettingsValues($settings)
    {
        if (filter_var($settings['sp_entityid'], FILTER_VALIDATE_URL) === false) {
            throw new \Exception('Invalid SP Entity ID provided');
        }
        // Save entity id host url for other checks
        $host = parse_url($settings['sp_entityid'], PHP_URL_HOST);

        if (isset($settings['sp_attributeconsumingservice'])) {
            if (!is_array($settings['sp_attributeconsumingservice'])) {
                throw new \Exception('sp_attributeconsumingservice should be an array');
            }
            array_walk($settings['sp_attributeconsumingservice'], function ($acs) {
                if (!is_array($acs)) {
                    throw new \Exception('sp_attributeconsumingservice elements should be an arrays');
                }
                array_walk($acs, function ($field) {
                    if (!in_array($field, self::$validAttributeFields)) {
                        throw new \Exception('Invalid Attribute field '. $field .' requested');
                    }
                });
            });
        }

        if (!is_array($settings['sp_assertionconsumerservice'])) {
            throw new \Exception('sp_assertionconsumerservice should be an array');
        }
        array_walk($settings['sp_assertionconsumerservice'], function ($acs) use ($host) {
            if (strpos($acs, $host) === false) {
                throw new \Exception('sp_assertionconsumerservice elements Location domain should be ' . $host .
                    ', got ' .  parse_url($acs, PHP_URL_HOST) . 'instead');
            }
        });

        if (!is_array($settings['sp_singlelogoutservice'])) {
            throw new \Exception('sp_singlelogoutservice should be an array');
        }
        array_walk($settings['sp_singlelogoutservice'], function ($slo) use ($host) {
            if (!is_array($slo)) {
                throw new \Exception('sp_singlelogoutservice elements should be arrays');
            }
            if (count($slo) != 2) {
                throw new \Exception('sp_singlelogoutservice array elements should contain exactly 2 elements,\
                    in order SLO Location and Binding');
            }
            if (!is_string($slo[0]) || !is_string($slo[1])) {
                throw new \Exception('sp_singlelogoutservice array elements should contain 2 string values,\
                    in order SLO Location and Binding');
            }
            if (strcasecmp($slo[1], "POST") != 0 &&
                strcasecmp($slo[1], "REDIRECT") != 0 &&
                strcasecmp($slo[1], "") != 0) {
                throw new \Exception('sp_singlelogoutservice elements Binding value should be one of\
                    "POST", "REDIRECT", or "" (empty string, defaults to POST)');
            }
            if (strpos($slo[0], $host) === false) {
                throw new \Exception('sp_singlelogoutservice elements Location domain should be ' . $host .
                    ', got ' .  parse_url($slo[0], PHP_URL_HOST) . 'instead');
            }
        });
    }
}
