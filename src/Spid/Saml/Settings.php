<?php

namespace Italia\Spid\Spid\Saml;

class Settings
{
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
    public static function validateSettings(array $settings)
    {
        $missingSettings = array();
        $msg = 'Missing settings fields: ';
        array_walk(self::$validSettings, function ($v, $k) use ($missingSettings, $settings) {
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
    }

    public static function cleanOpenSsl($file)
    {
        $k = file_get_contents($file);
        $ck = '';
        foreach (preg_split("/((\r?\n)|(\r\n?))/", $k) as $l) {
            if (strpos($l, '-----') === false) {
                $ck .= $l;
            }
        }
        return $ck;
    }
}
