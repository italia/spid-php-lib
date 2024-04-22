<?php

declare(strict_types=1);

require_once __DIR__ . "/LoggerMock.php";

final class SpTest extends PHPUnit\Framework\TestCase
{
    private static $settings = [
        'sp_entityid' => 'http://sp3.simevo.com/',
        'sp_key_file' => './example/test_sp.key',
        'sp_cert_file' => './example/test_sp.crt',
        'sp_assertionconsumerservice' => ['http://sp3.simevo.com/acs'],
        'sp_singlelogoutservice' => [
            ['http://sp3.simevo.com/slo', ''],
            ['http://sp3.simevo.com/slo', 'REDIRECT']
        ],
        'sp_org_name' => 'test_simevo',
        'sp_org_display_name' => 'Test Simevo',
        'sp_key_cert_values' => [
            'countryName' => 'IT',
            'stateOrProvinceName' => 'Milan',
            'localityName' => 'Milan',
            'commonName' => 'Name',
            'emailAddress' => 'test@test.com',
        ],
        'idp_metadata_folder' => './example/idp_metadata/',
        'sp_attributeconsumingservice' => [
            ["name", "familyName", "fiscalNumber", "email"],
            ["name", "familyName", "fiscalNumber", "email", "spidCode"]
            ]
        ];

    private static $idps = [];

    public static function setupIdps()
    {
        self::$idps = glob(SpTest::$settings['idp_metadata_folder'] . "*.xml");
        // If no IDP is found, download production IDPs for tests
        if (count(self::$idps) == 0) {
            exec('php ./bin/download_idp_metadata.php ./example/idp_metadata/');
            self::$idps = glob(SpTest::$settings['idp_metadata_folder'] . "*.xml");
            return true;
        }
        return false;
    }

    public function testCanBeCreatedFromValidSettings()
    {
        $this->assertInstanceOf(
            Italia\Spid\Sp::class,
            new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings)
        );
        $this->assertIsReadable(self::$settings['sp_key_file']);
        $this->assertIsReadable(self::$settings['sp_cert_file']);

        unlink(self::$settings['sp_key_file']);
        unlink(self::$settings['sp_cert_file']);
    }

    public function testCanBeCreatedWithoutAutoconfigure()
    {
        $settings = SpTest::$settings;
        $settings['sp_key_file'] = './some/location/sp.key';
        $settings['sp_cert_file'] = './some/location/sp.crt';
        $this->assertInstanceOf(
            Italia\Spid\Sp::class,
            new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings, null, false)
        );
        $this->assertFalse(is_readable($settings['sp_key_file']));
        $this->assertFalse(is_readable($settings['sp_cert_file']));
    }

    private function validateXml($xmlString, $schemaFile, $valid = true)
    {
        $xml = new DOMDocument();
        $xml->loadXML($xmlString, LIBXML_NOBLANKS);
        $this->assertEquals($xml->schemaValidate($schemaFile), $valid);
    }

    public function testMetatadaValid()
    {
        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);
        $metadata = $sp->getSPMetadata();
        $this->validateXml($metadata, "./tests/schemas/saml-schema-metadata-SPID-SP.xsd");
    }

    public function testSettingsWithoutEntityId()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_entityid']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp(new LoggerMock(), $settings1);
    }

    public function testSettingsWithoutSpKeyFile()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_key_file']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp(new LoggerMock(),  $settings1);
    }

    public function testSettingsWithoutSpCertFile()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_cert_file']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp(new LoggerMock(),  $settings1);
    }

    public function testSettingsWithoutAssertionConsumerService()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_assertionconsumerservice']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp(new LoggerMock(),  $settings1);
    }

    public function testSettingsWithoutSingleLogoutService()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['sp_singlelogoutservice']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp(new LoggerMock(),  $settings1);
    }

    public function testSettingsWithoutIdpMetadataFolder()
    {
        $settings1 = SpTest::$settings;
        unset($settings1['idp_metadata_folder']);
        $this->expectException(\Exception::class);
        $sp = new Italia\Spid\Sp(new LoggerMock(),  $settings1);
    }

    public function testSettingsWithInvalidSPEntityid()
    {
        $this->expectException(InvalidArgumentException::class);
        $settings = self::$settings;
        $settings['sp_entityid'] = "htp:/simevo";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithInvalidComparison()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_comparison'] = "invalid";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithInvalidSpACS()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_assertionconsumerservice'] = "not an array";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_assertionconsumerservice'] = [];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_assertionconsumerservice'] = [
            'http://wrong.url.com/acs'
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithInvalidSpSLO()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = "not an array";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            'not an array'
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            []
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['too', 'many', 'elements']
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['both elements should be strings', 1]
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['http://wrong.url.com', '']
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_singlelogoutservice'] = [
            ['http://sp3.simevo.com/slo', 'invalid binding']
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithInvalidSpAttrCS()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = "not an array";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            'not an array'
        ];
        new Italia\Spid\Sp(new LoggerMock(),  $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            'not an array'
        ];
        new Italia\Spid\Sp(new LoggerMock(), $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            []
        ];
        new Italia\Spid\Sp(new LoggerMock(), $settings);

        $this->expectException(InvalidArgumentException::class);
        $settings['sp_attributeconsumingservice'] = [
            ['invalid name']
        ];
        new Italia\Spid\Sp(new LoggerMock(), $settings);
    }

    public function testSettingsWithInvalidKey()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_key_file'] = "/invalid/path/sp.key";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithInvalidCert()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['sp_cert_file'] = "/invalid/path/sp.cert";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithInvalidIdpMetaFolder()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['idp_metadata_folder'] = "/invalid/path/idp_metadata";
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithCrapAcss()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['accepted_clock_skew_seconds'] = 'zero';
        new Italia\Spid\Sp(new LoggerMock(),  $settings);
    }

    public function testSettingsWithNegativeAcss()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['accepted_clock_skew_seconds'] = -1;
        new Italia\Spid\Sp(new LoggerMock(), $settings);
    }

    public function testSettingsWithLudicrousAcss()
    {
        $settings = self::$settings;
        $this->expectException(InvalidArgumentException::class);
        $settings['accepted_clock_skew_seconds'] = 3000;
        new Italia\Spid\Sp(new LoggerMock(),$settings);
    }

    public function testCanLoadAllIdpMetadata()
    {
        $sp = new Italia\Spid\Sp(new LoggerMock(),SpTest::$settings);
        $result = self::setupIdps();
        foreach (self::$idps as $idp) {
            $retrievedIdp = $sp->loadIdpFromFile($idp);
            $this->assertEquals($retrievedIdp->idpFileName, $idp);
            $idpEntityId = $retrievedIdp->metadata['idpEntityId'];
            $host = parse_url($idpEntityId, PHP_URL_HOST);
            $host = implode('.', array_slice(explode('.', $host), -2, 2));
            $idpSSOArray = $retrievedIdp->metadata['idpSSO'];
            foreach ($idpSSOArray as $idpSSO) {
                $location = parse_url($idpSSO['location'], PHP_URL_HOST);
                $location = implode('.', array_slice(explode('.', $location), -2, 2));
                $this->assertStringContainsString($host, $location);
            }
            $idpSLOArray = $retrievedIdp->metadata['idpSLO'];
            foreach ($idpSLOArray as $idpSLO) {
                $location = parse_url($idpSLO['location'], PHP_URL_HOST);
                $location = implode('.', array_slice(explode('.', $location), -2, 2));
                $this->assertStringContainsString($host, $location);
            }
        }
        // If IDPs were downloaded for testing purposes, then delete them
        if ($result) {
            array_map('unlink', self::$idps);
        }
    }

    public function testIsAuthenticatedNoIDP()
    {
        $sp = new Italia\Spid\Sp(new LoggerMock(),SpTest::$settings);
        $this->assertFalse($sp->isAuthenticated());
    }

    public function testIsAuthenticatedInvalidIDP()
    {
        unset($_SESSION);
        $sp = new Italia\Spid\Sp(new LoggerMock(),SpTest::$settings);
        $_SESSION['idpName'] = null;
        $this->assertFalse($sp->isAuthenticated());
    }

    public function testIsAuthenticatedInvalidSession()
    {
        unset($_SESSION);
        $result = self::setupIdps();

        $sp = new Italia\Spid\Sp(new LoggerMock(),SpTest::$settings);
        $session = new Italia\Spid\Spid\Session();
        $session->idp = self::$idps[0];
        // IF these values are not set, the session is invalid
        // $session->idpEntityID = 'https:/sp.example.com/';
        // $session->level = 1;
        // $session->sessionID = 'test123';
        $_SESSION['spidSession'] = (array)$session;
        $this->assertFalse($sp->isAuthenticated());

        // If IDPs were downloaded for testing purposes, then delete them
        if ($result) {
            array_map('unlink', self::$idps);
        }
    }

    public function testIsAuthenticatedInvalidResponse()
    {
        unset($_SESSION);
        $sp = new Italia\Spid\Sp(new LoggerMock(),SpTest::$settings);
        $_POST['SAMLResponse'] = "";
        $this->assertFalse($sp->isAuthenticated());
        unset($_POST['SAMLResponse']);
    }

    public function testIsAuthenticatedLogoutResponse()
    {
        unset($_SESSION);
        $result = self::setupIdps();

        $sp = new Italia\Spid\Sp(new LoggerMock(),SpTest::$settings);
        $_SESSION['idpName'] = self::$idps[0];
        $_SESSION['inResponseTo'] = "PROVA";
        $this->assertFalse($sp->isAuthenticated());

        // If IDPs were downloaded for testing purposes, then delete them
        if ($result) {
            array_map('unlink', self::$idps);
        }
    }

    public function testIsAuthenticated()
    {
        unset($_SESSION);
        $result = self::setupIdps();

        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);
        $session = new Italia\Spid\Spid\Session();
        $session->idp = self::$idps[0];
        $session->idpEntityID = 'https:/sp.example.com/';
        $session->level = 1;
        $session->sessionID = 'test123';
        $_SESSION['spidSession'] = (array)$session;
        $this->assertTrue($sp->isAuthenticated());

        // If IDPs were downloaded for testing purposes, then delete them
        if ($result) {
            array_map('unlink', self::$idps);
        }
    }

    public function testGetAttributesNoAuth()
    {
        unset($_SESSION);
        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);
        $this->assertFalse($sp->isAuthenticated());
        $this->assertEquals([], $sp->getAttributes());
    }

    public function testGetAttributes()
    {

        unset($_SESSION);
        $result = self::setupIdps();

        // Authenticate first
        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);
        $session = new Italia\Spid\Spid\Session();
        $session->idp = self::$idps[0];
        $session->idpEntityID = 'https:/sp.example.com/';
        $session->level = 1;
        $session->sessionID = 'test123';
        // Test with no attributes requested first
        $_SESSION['spidSession'] = (array)$session;
        $this->assertTrue($sp->isAuthenticated());
        // Authentication completed, request attributes
        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);
        $this->assertIsArray($sp->getAttributes());
        $this->assertCount(0, $sp->getAttributes());
        //  No test with attributes requested
        $session->attributes = [
            'name' => 'Test'
        ];
        $_SESSION['spidSession'] = (array)$session;
        $this->assertIsArray($sp->getAttributes());
        $this->assertCount(1, $sp->getAttributes());

        // If IDPs were downloaded for testing purposes, then delete them
        if ($result) {
            array_map('unlink', self::$idps);
        }
    }

    public function testLoginInvalidACS()
    {
        unset($_SESSION);
        $result = self::setupIdps();

        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);

        $this->expectException(\Exception::class);
        $sp->login(self::$idps[0], 12, 0);
    }

    public function testLoginInvalidAttrCS()
    {
        unset($_SESSION);
        $result = self::setupIdps();

        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);

        $this->expectException(\Exception::class);
        $sp->login(self::$idps[0], 0, 12);
    }

    public function testLoginAlreadyAuthenticated()
    {
        unset($_SESSION);
        $result = self::setupIdps();

        $sp = new Italia\Spid\Sp(new LoggerMock(), SpTest::$settings);
        $session = new Italia\Spid\Spid\Session();
        $session->idp = self::$idps[0];
        $session->idpEntityID = 'https:/sp.example.com/';
        $session->level = 1;
        $session->sessionID = 'test123';
        $_SESSION['spidSession'] = (array)$session;
        $this->assertTrue($sp->isAuthenticated());

        $this->assertFalse($sp->login(self::$idps[0], 0, 0));
        // If IDPs were downloaded for testing purposes, then delete them
        if ($result) {
            array_map('unlink', self::$idps);
        }
    }

    public static function tearDownAfterClass(): void
    {
        unlink(self::$settings['sp_key_file']);
        unlink(self::$settings['sp_cert_file']);
    }
}
