<?php

declare(strict_types=1);

require_once __DIR__ . "/LoggerMock.php";

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

    private static $idps = [];

    public static function setupIdps()
    {
        self::$idps = glob(IdpTest::$settings['idp_metadata_folder'] . "*.xml");
        // If no IDP is found, download production IDPs for tests
        if (count(self::$idps) == 0) {
            exec('php ./bin/download_idp_metadata.php ./example/idp_metadata/');
            self::$idps = glob(IdpTest::$settings['idp_metadata_folder'] . "*.xml");
            return true;
        }
        return false;
    }

    public function testCanBeCreatedFromValidSP()
    {
        $sp = new Italia\Spid\Sp(new LoggerMock(), IdpTest::$settings);
        $this->assertInstanceOf(
            Italia\Spid\Spid\Saml\Idp::class,
            new Italia\Spid\Spid\Saml\Idp($sp)
        );
    }

    public function testCanLoadFromValidXML()
    {
        $result = self::setupIdps();

        $sp = new Italia\Spid\Spid\Saml(new LoggerMock(), IdpTest::$settings);
        $idp = new Italia\Spid\Spid\Saml\Idp($sp);
        $loaded = $idp->loadFromXml(self::$idps[0]);
        $this->assertInstanceOf(
            Italia\Spid\Spid\Saml\Idp::class,
            $loaded
        );
        $this->assertNotEmpty($idp->idpFileName);
        $this->assertNotEmpty($idp->metadata);

        // If IDPs were downloaded for testing purposes, then delete them
        if ($result) {
            array_map('unlink', self::$idps);
        }
    }

    public function testCanLoadFromValidXMLFullPath()
    {
        $sp = new Italia\Spid\Spid\Saml(new LoggerMock(), IdpTest::$settings);
        $idp = new Italia\Spid\Spid\Saml\Idp($sp);
        $loaded = $idp->loadFromXml(self::$idps[0]);
        $this->assertInstanceOf(
            Italia\Spid\Spid\Saml\Idp::class,
            $loaded
        );
        $this->assertNotEmpty($idp->idpFileName);
        $this->assertNotEmpty($idp->metadata);
    }

    public function testLoadXMLWIthWrongFilePath()
    {
        $sp = new Italia\Spid\Spid\Saml(new LoggerMock(), IdpTest::$settings);
        $idp = new Italia\Spid\Spid\Saml\Idp($sp);
        $sp->settings['idp_metadata_folder'] = '/wrong/path/to/metadata/';

        $this->expectException(\Exception::class);
        $idp->loadFromXml(self::$idps[0]);

        $this->assertNotEmpty($idp);
        $this->assertNotEmpty($idp);
    }

    // TODO check if logout response should redirect
}
