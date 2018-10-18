<?php
declare(strict_types=1);

require_once(__DIR__ . "/../vendor/autoload.php");

final class SpTest extends PHPUnit\Framework\TestCase
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

    public function testCanBeCreatedFromValidSettings()
    {
        $this->assertInstanceOf(
            Italia\Spid\Sp::class,
            new Italia\Spid\Sp(SpTest::$settings)
        );
    }

    private function validateXml($xmlString, $schemaFile, $valid = true)
    {
        $xml = new DOMDocument();
        $xml->loadXML($xmlString, LIBXML_NOBLANKS);
        $this->assertEquals($xml->schemaValidate($schemaFile), $valid);
    }

    public function testMetatadaValid()
    {
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $metadata = $sp->getSPMetadata();
        $this->validateXml($metadata, "./tests/schemas/saml-schema-metadata-SPID-SP.xsd");
    }

    public function testSettingsWithoutEntityId()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_entityid']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp($settings1);
    }

    public function testSettingsWithoutSpKeyFile()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_key_file']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp($settings1);
    }

    public function testSettingsWithoutSpCertFile()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_cert_file']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp($settings1);
    }

    public function testSettingsWithoutAssertionConsumerService()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_assertionconsumerservice']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp($settings1);
    }

    public function testSettingsWithoutSingleLogoutService()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_singlelogoutservice']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp($settings1);
    }

    public function testSettingsWithoutIdpMetadataFolder()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['idp_metadata_folder']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp($settings1);
    }

    public function testCanLoadAllIdpMetadata()
    {
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $idps = $files = glob(SpTest::$settings['idp_metadata_folder'] . "*.xml");
        foreach ($idps as $idp) {
            $retrievedIdp = $sp->loadIdpFromFile($idp);
            $this->assertEquals($retrievedIdp->idpFileName, $idp);
            $idpEntityId = $retrievedIdp->metadata['idpEntityId'];
            $host = parse_url($idpEntityId, PHP_URL_HOST);
            $idpSSOArray = $retrievedIdp->metadata['idpSSO'];
            foreach ($idpSSOArray as $key => $idpSSO) {
                $this->assertContains($host, $idpSSO['location']);
            }
            $idpSLOArray = $retrievedIdp->metadata['idpSLO'];
            foreach ($idpSLOArray as $key => $idpSLO) {
                $this->assertContains($host, $idpSLO['location']);
            }
        }
    }
}
