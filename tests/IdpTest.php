<?php
declare(strict_types=1);

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
        'idp_metadata_folder' => './tests/fixtures/idp_metadata/',
        'sp_attributeconsumingservice' => [
            ["name", "familyName", "fiscalNumber", "email"],
            ["name", "familyName", "fiscalNumber", "email", "spidCode"]
            ]
        ];

    private static $idps = [];

    // see the note on SpTest::setupIdps(): the suite runs against committed fixtures, never
    // against the live SPID registry
    public static function setupIdps()
    {
        self::$idps = glob(IdpTest::$settings['idp_metadata_folder'] . "*.xml");
        return self::$idps;
    }

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
        self::setupIdps();
        $this->assertNotEmpty(self::$idps);

        $sp = new Italia\Spid\Spid\Saml(IdpTest::$settings);
        $idp = new Italia\Spid\Spid\Saml\Idp($sp);
        $loaded = $idp->loadFromXml(self::$idps[0]);
        $this->assertInstanceOf(
            Italia\Spid\Spid\Saml\Idp::class,
            $loaded
        );
        $this->assertNotEmpty($idp->idpFileName);
        $this->assertNotEmpty($idp->metadata);
    }

    public function testCanLoadFromValidXMLFullPath()
    {
        self::setupIdps();

        $sp = new Italia\Spid\Spid\Saml(IdpTest::$settings);
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
        self::setupIdps();

        $sp = new Italia\Spid\Spid\Saml(IdpTest::$settings);
        $idp = new Italia\Spid\Spid\Saml\Idp($sp);
        $sp->settings['idp_metadata_folder'] = '/wrong/path/to/metadata/';

        $this->expectException(\Exception::class);
        $idp->loadFromXml(self::$idps[0]);

        $this->assertNotEmpty($idp);
        $this->assertNotEmpty($idp);
    }

    // TODO check if logout response should redirect
}
