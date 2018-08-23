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
        'sp_singlelogoutservice' => 'http://sp3.simevo.com/slo',
        'sp_org_name' => 'test_simevo',
        'sp_org_display_name' => 'Test Simevo',
        'idp_metadata_folder' => './example/idp_metadata/',
        'sp_attributeconsumingservice' => [
            ["name", "familyName", "fiscalNumber", "email"],
            ["name", "familyName", "fiscalNumber", "email", "spidCode"]
            ]
        ];
    
    public function testCanBeCreatedFromValidSettings(): void
    {
        $this->assertInstanceOf(
            Italia\Spid\Sp::class,
            new Italia\Spid\Sp(SpTest::$settings)
        );
    }

    private function validateXml($xmlString, $schemaFile, $valid = true): void
    {
        $xml = new DOMDocument();
        $xml->loadXML($xmlString, LIBXML_NOBLANKS);
        $this->assertEquals($xml->schemaValidate($schemaFile), $valid);
    }

    public function testMetatadaValid(): void
    {
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $metadata = $sp->getSPMetadata();
        $this->validateXml($metadata, "./tests/schemas/saml-schema-metadata-SPID-SP.xsd");
    }

    public function testCanLoadAllIdpMetadata(): void
    {
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $idps = ['idp_1', 'idp_2', 'idp_3', 'idp_4', 'idp_5', 'idp_6', 'idp_7', 'idp_8', 'testenv2'];
        foreach ($idps as $idp) {
            $sp->loadIdpFromFile($idp);
            $retrievedIdp = $sp->getIdp($idp);
            $this->assertEquals($retrievedIdp->idpFileName, $idp);
            // var_dump($retrievedIdp);
            $idpEntityId = $retrievedIdp->metadata['idpEntityId'];
            $idpSSO = $retrievedIdp->metadata['idpSSO'];
            $this->assertContains($idpEntityId, $idpSSO);
            $idpSLO = $retrievedIdp->metadata['idpSLO'];
            $this->assertContains($idpEntityId, $idpSLO);
        }
    }

    public function testSettingsWithoutEntityId(): void
    {
        // TODO check other missing keys:
        // sp_key_file
        // sp_cert_file
        // sp_assertionconsumerservice
        // sp_singlelogoutservice
        // sp_org_name
        // sp_org_display_name
        // idp_metadata_folder
        // sp_attributeconsumingservice
        $settings1 = SpTest::$settings;
        unset($settings1['sp_entityid']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp($settings1);
    }
}
