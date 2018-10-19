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

    public function testSettingsWithInvalidSPEntityid()
    {
        $this->expectException(InvalidArgumentException::class);
        $settings = self::$settings;
        $settings['sp_entityid'] = "htp:/simevo";
        new Italia\Spid\Sp($settings);  
    }

    public function testSettingsWithInvalidSpACS()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_assertionconsumerservice'] = "not an array";
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_assertionconsumerservice'] = [];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_assertionconsumerservice'] = [
            'http://wrong.url.com/acs'
        ];
        new Italia\Spid\Sp($settings);  
    }

    public function testSettingsWithInvalidSpSLO()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = "not an array";
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            'not an array'
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            []
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['too', 'many', 'elements']
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['both elements should be strings', 1]
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['http://wrong.url.com', '']
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['http://sp3.simevo.com/slo', 'invalid binding']
        ];
        new Italia\Spid\Sp($settings);
    }

    public function testSettingsWithInvalidSpAttrCS()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = "not an array";
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            'not an array'
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            'not an array'
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            []
        ];
        new Italia\Spid\Sp($settings);  

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            ['invalid name']
        ];
        new Italia\Spid\Sp($settings);  
    }

    public function testSettingsWithInvalidKey()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_key_file'] = "/invalid/path/sp.key";
        new Italia\Spid\Sp($settings);  
    }

    public function testSettingsWithInvalidCert()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_cert_file'] = "/invalid/path/sp.cert";
        new Italia\Spid\Sp($settings);  
    }

    public function testSettingsWithInvalidIdpMetaFolder()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['idp_metadata_folder'] = "/invalid/path/idp_metadata";
        new Italia\Spid\Sp($settings);  
    }

    public function testCanLoadAllIdpMetadata()
    {
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $idps = glob(SpTest::$settings['idp_metadata_folder'] . "*.xml");
        // If no IDP is found, download production IDPs for tests
        if (count($idps) == 0) {
            $delete = true;
            exec('php ./bin/download_idp_metadata.php ./example/idp_metadata/');
        }
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
        // If IDPs were downloaded for testing purposes, then delete them
        if (isset($delete) && $delete) {
            array_map('unlink', $idps);
        }
    }

    public function testIsAuthenticatedNoIDP()
    {
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $this->assertEquals(false, $sp->isAuthenticated());
    }

    public function testIsAuthenticatedInvalidIDP()
    {
        session_unset();
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $_SESSION['idpName'] = null;
        $this->assertEquals(false, $sp->isAuthenticated());
    }

    public function testIsAuthenticatedInvalidSession()
    {
        session_unset();
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $session = new Italia\Spid\Spid\Session();
        $session->idp = 'testenv';
        // IF these values are not set, the session is invalid
        // $session->idpEntityID = 'https:/sp.example.com/';
        // $session->level = 1;
        // $session->sessionID = 'test123';
        $_SESSION['spidSession'] = $session;
        $this->assertEquals(false, $sp->isAuthenticated());
    }

    public function testIsAuthenticatedInvalidResponse()
    {
        session_unset();
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $_POST['SAMLResponse'] = "";
        $this->assertEquals(false, $sp->isAuthenticated());
        unset($_POST['SAMLResponse']);
    }

    public function testIsAuthenticatedLogoutResponse()
    {
        session_unset();
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $_SESSION['idpName'] = "testenv";
        $_SESSION['inResponseTo'] = "PROVA";
        $this->assertEquals(false, $sp->isAuthenticated());
    }

    public function testIsAuthenticated()
    {
        session_unset();
        $sp = new Italia\Spid\Sp(SpTest::$settings);
        $session = new Italia\Spid\Spid\Session();
        $session->idp = 'testenv';
        $session->idpEntityID = 'https:/sp.example.com/';
        $session->level = 1;
        $session->sessionID = 'test123';
        $_SESSION['spidSession'] = $session;
        $this->assertEquals(true, $sp->isAuthenticated());
    }
}
