<?php
declare(strict_types=1);

require_once(__DIR__ . "/../vendor/autoload.php");

final class IdpTest extends PHPUnit\Framework\TestCase
{
    private static $settings = [
        'sp_entityid' => 'http://sp3.simevo.com/',
        'sp_key_file' => './example/sp.key',
        'sp_cert_file' => './example/sp.crt',
        'sp_assertionconsumerservice' => ['http://sp3.simevo.com/acs'],
        'sp_singlelogoutservice' => [
            ['http://sp3.simevo.com/slo', ''],
            ['http://sp3.simevo.com/slo', 'REDIRECT']
        ],
        'sp_org_name' => 'test_simevo',
        'sp_org_display_name' => 'Test Simevo',
        'idp_metadata_folder' => './example/idp_metadata/',
        'sp_attributeconsumingservice' => [
            ["name", "familyName", "fiscalNumber", "email"],
            ["name", "familyName", "fiscalNumber", "email", "spidCode"]
            ]
        ];

    public function testCanBeCreatedFromValidSP()
    {
       $sp = new Italia\Spid\Sp(IdpTest::$settings);
       $this->assertInstanceOf(
            Italia\Spid\Spid\Saml\Idp::class,
            new Italia\Spid\Spid\Saml\Idp($sp)
        );
    }

    public function testCanLoadFromValidXML()
    {
        $sp = new Italia\Spid\Sp(IdpTest::$settings);
        $idp = new Italia\Spid\Spid\Saml\Idp($sp);
        $loaded = $idp->loadFromXml('testenv');
        $this->assertInstanceOf(
            Italia\Spid\Spid\Saml\Idp::class,
            $loaded
        );
        $this->assertAttributeNotEmpty('idpFileName', $idp);
        $this->assertAttributeNotEmpty('metadata', $idp);
    }
}