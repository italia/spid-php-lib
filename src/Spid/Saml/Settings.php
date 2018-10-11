<?php

namespace Italia\Spid\Spid\Saml;

class Settings
{
    const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    // Settings with value 1 are mandatory
    private static $validSettings = [
        'sp_entityid' => 1,
        'sp_key_file' => 1,
        'sp_cert_file' => 1,
        'sp_assertionconsumerservice' => 1,
        'sp_singlelogoutservice' => 1,
        'sp_attributeconsumingservice' => 0,
        'sp_org_name' => 0,
        'sp_org_display_name' => 0,
        'idp_metadata_folder' => 1
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
            if (self::$validSettings[$k] == 1 && !array_key_exists($k, $settings)) {
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

        self::checkSettingsValus($settings);
    }

    public static function cleanOpenSsl($file, $isCert = false)
    {
        if ($isCert) {
            $k = $file;
        } else {
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
        if (filter_var($settings[''], FILTER_VALIDATE_URL) === false)
            throw new \Exception('Invalid SP Entity ID provided');
        if (isset($settings['sp_attributeconsumingservice'])) {
           if (!is_array($settings['sp_attributeconsumingservice'])) throw new \Exception('sp_attributeconsumingservice should be an array');
           array_walk($settings['sp_attributeconsumingservice'], function($acs) {
                if (!is_array($acs)) throw new \Exception('sp_attributeconsumingservice elements should be an arrays');
                array_walk($acs, function($field) {
                    if (!in_array($field, self::$validAttributeFields)) throw new \Exception('Invalid Attribute field '. $field .' requested');
                });
           });
        }
        

    }
}
