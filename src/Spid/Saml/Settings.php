<?php

namespace Italia\Spid\Spid\Saml;

use Exception;
use InvalidArgumentException;

class Settings
{
    public const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    public const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    public const REQUIRED = 1;
    public const NOT_REQUIRED = 0;
    // Settings with value 1 are mandatory
    private static $validSettings = [
        'sp_entityid' => self::REQUIRED,
        'sp_key_file' => self::REQUIRED,
        'sp_cert_file' => self::REQUIRED,
        'sp_comparison' => self::NOT_REQUIRED,
        'sp_assertionconsumerservice' => self::REQUIRED,
        'sp_singlelogoutservice' => self::REQUIRED,
        'sp_attributeconsumingservice' => self::NOT_REQUIRED,
        'sp_org_name' => self::NOT_REQUIRED,
        'sp_org_display_name' => self::NOT_REQUIRED,
        'sp_key_cert_values' => [
            self::NOT_REQUIRED => [
                'countryName' => self::REQUIRED,
                'stateOrProvinceName' => self::REQUIRED,
                'localityName' => self::REQUIRED,
                'commonName' => self::REQUIRED,
                'emailAddress' => self::REQUIRED
            ]
        ],
        'idp_metadata_folder' => self::REQUIRED,
        'accepted_clock_skew_seconds' => self::NOT_REQUIRED,
        // aggregator
        'sp_contact_aggregator_company' => self::NOT_REQUIRED,
        'sp_contact_aggregator_person_type' => self::NOT_REQUIRED,
        'sp_contact_aggregator_person_vat_number' => self::NOT_REQUIRED,
        'sp_contact_aggregator_person_fiscal_code' => self::NOT_REQUIRED,
        'sp_contact_aggregator_person_email' => self::NOT_REQUIRED,
        'sp_contact_aggregator_person_phone' => self::NOT_REQUIRED,
        // aggregate
        'sp_contact_aggregate_ipa_code' => self::NOT_REQUIRED,
        'sp_contact_aggregate_person_type' => self::NOT_REQUIRED,
        'sp_contact_aggregate_company' => self::NOT_REQUIRED
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

    /**
     * @throws Exception
     */
    public static function validateSettings(array $settings)
    {
        $missingSettings = [];
        $msg = 'Missing settings fields: ';
        array_walk(self::$validSettings, function ($v, $k) use (&$missingSettings, &$settings) {
            $settingRequired = self::$validSettings[$k];
            $childSettings = [];
            if (is_array($v) && isset($v[self::REQUIRED])) {
                $settingRequired = self::REQUIRED;
                $childSettings[$k] = $v[self::REQUIRED];
            }
            if ($settingRequired == self::REQUIRED && !array_key_exists($k, $settings)) {
                $missingSettings[$k] = 1;
            } else {
                foreach ($childSettings as $key => $value) {
                    if ($value == self::REQUIRED && !array_key_exists($key, $settings[$k])) {
                        $missingSettings[$key] = 1;
                    }
                }
            }
        });
        foreach ($missingSettings as $k => $v) {
            $msg .= $k . ', ';
        }
        if (count($missingSettings) > 0) {
            throw new Exception($msg);
        }

        $invalidFields = array_diff_key($settings, self::$validSettings);
        // Check for settings that have child values
        array_walk(self::$validSettings, function ($v, $k) use (&$invalidFields, $settings) {
            // Child values found, check if settings array is set for that key
            if (is_array($v) && isset($settings[$k])) {
                // $v has at most 2 keys, self::REQUIRED and self::NOT_REQUIRED
                // do array_dif_key for both sub arrays
                $invalidFields = array_merge($invalidFields, array_diff_key($settings[$k], reset($v)));
                $invalidFields = array_merge($invalidFields, array_diff_key($settings[$k], end($v)));
            }
        });
        $msg = 'Invalid settings fields: ';
        foreach ($invalidFields as $k => $v) {
            $msg .= $k . ', ';
        }
        if (count($invalidFields) > 0) {
            throw new Exception($msg);
        }

        self::checkSettingsValues($settings);
    }

    /**
     * @throws Exception
     */
    public static function cleanOpenSsl($file, $isCert = false): string
    {
        if ($isCert) {
            $k = $file;
        } else {
            if (!is_readable($file)) {
                throw new Exception("File $file is not readable. Please check file permissions.");
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

    /**
     * @throws InvalidArgumentException
     */
    private static function checkSettingsValues($settings)
    {
        if (filter_var($settings['sp_entityid'], FILTER_VALIDATE_URL) === false) {
            throw new InvalidArgumentException('Invalid SP Entity ID provided');
        }
        // Save entity id host url for other checks
        $host = parse_url($settings['sp_entityid'], PHP_URL_HOST);

        if (!is_readable($settings['idp_metadata_folder'])) {
            throw new InvalidArgumentException('Idp metadata folder does not exist or is not readable.');
        }
        if (isset($settings['sp_attributeconsumingservice'])) {
            if (!is_array($settings['sp_attributeconsumingservice'])) {
                throw new InvalidArgumentException('sp_attributeconsumingservice should be an array');
            }
            array_walk($settings['sp_attributeconsumingservice'], function ($acs) {
                if (!is_array($acs)) {
                    throw new InvalidArgumentException('sp_attributeconsumingservice elements should be an arrays');
                }
                if (count($acs) == 0) {
                    throw new InvalidArgumentException(
                        'sp_attributeconsumingservice elements should contain at least one element'
                    );
                }
                array_walk($acs, function ($field) {
                    if (!in_array($field, self::$validAttributeFields)) {
                        throw new InvalidArgumentException("Invalid Attribute field $field requested");
                    }
                });
            });
        }

        if (!is_array($settings['sp_assertionconsumerservice'])) {
            throw new InvalidArgumentException('sp_assertionconsumerservice should be an array');
        }
        if (count($settings['sp_assertionconsumerservice']) == 0) {
            throw new InvalidArgumentException('sp_assertionconsumerservice should contain at least one element');
        }
        array_walk($settings['sp_assertionconsumerservice'], function ($acs) use ($host) {
            if (strpos($acs, $host) === false) {
                throw new InvalidArgumentException(
                    "sp_assertionconsumerservice elements Location domain should be $host, got " .
                    parse_url($acs, PHP_URL_HOST) . ' instead'
                );
            }
        });

        if (!is_array($settings['sp_singlelogoutservice'])) {
            throw new InvalidArgumentException('sp_singlelogoutservice should be an array');
        }
        if (count($settings['sp_singlelogoutservice']) == 0) {
            throw new InvalidArgumentException('sp_singlelogoutservice should contain at least one element');
        }
        array_walk($settings['sp_singlelogoutservice'], function ($slo) use ($host) {
            if (!is_array($slo)) {
                throw new InvalidArgumentException('sp_singlelogoutservice elements should be arrays');
            }
            if (count($slo) != 2) {
                throw new InvalidArgumentException(
                    'sp_singlelogoutservice array elements should contain exactly 2 elements, ' .
                    'in order SLO Location and Binding'
                );
            }
            if (!is_string($slo[0]) || !is_string($slo[1])) {
                throw new InvalidArgumentException(
                    'sp_singlelogoutservice array elements should contain 2 string values, ' .
                    'in order SLO Location and Binding'
                );
            }
            if (
                strcasecmp($slo[1], "POST") != 0 &&
                strcasecmp($slo[1], "REDIRECT") != 0 &&
                strcasecmp($slo[1], "") != 0
            ) {
                throw new InvalidArgumentException(
                    'sp_singlelogoutservice elements Binding value should be one of "POST", "REDIRECT", ' .
                    'or "" (empty string, defaults to POST)'
                );
            }
            if (strpos($slo[0], $host) === false) {
                throw new InvalidArgumentException(
                    "sp_singlelogoutservice elements Location domain should be $host, got " .
                    parse_url($slo[0], PHP_URL_HOST) . 'instead'
                );
            }
        });
        if (isset($settings['sp_key_cert_values'])) {
            if (!is_array($settings['sp_key_cert_values'])) {
                throw new InvalidArgumentException('sp_key_cert_values should be an array');
            }
            if (count($settings['sp_key_cert_values']) != 5) {
                throw new InvalidArgumentException(
                    'sp_key_cert_values should contain 5 values: ' .
                    'countryName, stateOrProvinceName, localityName, commonName, emailAddress'
                );
            }
            foreach ($settings['sp_key_cert_values'] as $key => $value) {
                if (!is_string($value)) {
                    throw new InvalidArgumentException(
                        "sp_key_cert_values values should be strings. Valued provided for key $key is not a string"
                    );
                }
            }
            if (strlen($settings['sp_key_cert_values']['countryName']) != 2) {
                throw new InvalidArgumentException(
                    'sp_key_cert_values countryName should be a 2 characters country code'
                );
            }
        }
        if (isset($settings['accepted_clock_skew_seconds'])) {
            if (!is_numeric($settings['accepted_clock_skew_seconds'])) {
                throw new InvalidArgumentException('accepted_clock_skew_seconds should be a number');
            }
            if ($settings['accepted_clock_skew_seconds'] < 0) {
                throw new InvalidArgumentException('accepted_clock_skew_seconds should be at least 0 seconds');
            }
            if ($settings['accepted_clock_skew_seconds'] > 300) {
                throw new InvalidArgumentException('accepted_clock_skew_seconds should be at most 300 seconds');
            }
        }
        if (isset($settings['sp_comparison'])) {
            if (
                strcasecmp($settings['sp_comparison'], "exact") != 0 &&
                strcasecmp($settings['sp_comparison'], "minimum") != 0 &&
                strcasecmp($settings['sp_comparison'], "better") != 0 &&
                strcasecmp($settings['sp_comparison'], "maximum") != 0
            ) {
                throw new InvalidArgumentException(
                    'sp_comparison value should be one of: "exact", "minimum", "better" or "maximum"'
                );
            }
        }
    }
}
