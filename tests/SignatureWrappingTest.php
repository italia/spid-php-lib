<?php

declare(strict_types=1);

use Italia\Spid\Spid\Saml\SignatureUtils;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for the SAML signature wrapping (XSW) vulnerability
 * (CWE-347 / CWE-349 / CWE-290).
 *
 * The library used to validate the signature of the genuine assertion while the
 * security checks and the attribute extraction read another, forged and unsigned,
 * assertion smuggled into the same response. These tests build a genuinely signed
 * response and a set of wrapping variations and assert that the honest response is
 * accepted while every forged one is rejected.
 */
final class SignatureWrappingTest extends TestCase
{
    private static $dir;
    private static $idpKey;
    private static $idpCert;
    private static $settings;

    private static $idpEntityId = 'https://idp.example.com/';
    private static $spEntityId = 'https://sp.example.com/';
    private static $acsUrl = 'https://sp.example.com/acs';
    private static $requestId = '_request0123456789abcdef';

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir() . '/spid_xsw_' . getmypid();
        @mkdir(self::$dir);
        @mkdir(self::$dir . '/idp_metadata');

        $kc = SignatureUtils::generateKeyCert([
            'sp_org_name' => 'idp',
            'sp_org_display_name' => 'idp',
            'sp_key_cert_values' => [
                'countryName' => 'IT',
                'stateOrProvinceName' => 'Rome',
                'localityName' => 'Rome',
                'commonName' => 'idp.example.com',
                'emailAddress' => 'idp@example.com',
            ],
        ]);
        self::$idpKey = self::$dir . '/idp.key';
        self::$idpCert = self::$dir . '/idp.crt';
        file_put_contents(self::$idpKey, $kc['key']);
        file_put_contents(self::$idpCert, $kc['cert']);

        $certClean = str_replace(
            ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"],
            '',
            $kc['cert']
        );
        $metadata = '<?xml version="1.0"?>'
            . '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
            . ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="' . self::$idpEntityId . '">'
            . '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
            . $certClean
            . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
            . '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
            . ' Location="' . self::$idpEntityId . 'slo"/>'
            . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
            . ' Location="' . self::$idpEntityId . 'sso"/>'
            . '</md:IDPSSODescriptor></md:EntityDescriptor>';
        file_put_contents(self::$dir . '/idp_metadata/idp.xml', $metadata);

        self::$settings = [
            'sp_entityid' => self::$spEntityId,
            'sp_key_file' => self::$dir . '/sp.key',
            'sp_cert_file' => self::$dir . '/sp.crt',
            'sp_assertionconsumerservice' => [self::$acsUrl],
            'sp_singlelogoutservice' => [[self::$spEntityId . 'slo', '']],
            'idp_metadata_folder' => self::$dir . '/idp_metadata/',
        ];

        // Start the PHP session up front so that populating $_SESSION in the
        // individual tests is not wiped by the session_start() the first Sp
        // instance would otherwise trigger.
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
    }

    public static function tearDownAfterClass(): void
    {
        foreach (glob(self::$dir . '/idp_metadata/*') ?: [] as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
        foreach (glob(self::$dir . '/*') ?: [] as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
        @rmdir(self::$dir . '/idp_metadata');
        @rmdir(self::$dir);
    }

    protected function tearDown(): void
    {
        // Do not leak session/request state into the other test classes: the
        // suite contains tests that assume an empty session.
        $_SESSION = [];
        unset($_POST['SAMLResponse'], $_GET['SAMLResponse']);
    }

    private function resetSession(): void
    {
        $_SESSION = [];
        $_SESSION['idpName'] = self::$dir . '/idp_metadata/idp.xml';
        $_SESSION['RequestID'] = self::$requestId;
        $_SESSION['acsUrl'] = self::$acsUrl;
        $_SESSION['idpEntityId'] = self::$idpEntityId;
        unset($_GET['SAMLResponse']);
    }

    /**
     * Builds a valid, standalone, signed <saml:Assertion>. $attrValue is the
     * identity the assertion carries. Overrides let a test flip a single field.
     */
    private function signedAssertion(string $attrValue, array $overrides = []): string
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $later = gmdate('Y-m-d\TH:i:s\Z', time() + 3600);
        $v = array_merge([
            'assertionId' => '_assertion0123456789abcdef',
            'idpEntityId' => self::$idpEntityId,
            'requestId' => self::$requestId,
            'acsUrl' => self::$acsUrl,
            'audience' => self::$spEntityId,
        ], $overrides);

        $assertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            . ' ID="' . $v['assertionId'] . '" Version="2.0" IssueInstant="' . $now . '">'
            . '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
            . $v['idpEntityId'] . '</saml:Issuer>'
            . '<saml:Subject>'
            . '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"'
            . ' NameQualifier="' . $v['idpEntityId'] . '">_transient-name-id</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData InResponseTo="' . $v['requestId'] . '"'
            . ' NotOnOrAfter="' . $later . '" Recipient="' . $v['acsUrl'] . '"/>'
            . '</saml:SubjectConfirmation></saml:Subject>'
            . '<saml:Conditions NotBefore="' . $now . '" NotOnOrAfter="' . $later . '">'
            . '<saml:AudienceRestriction><saml:Audience>' . $v['audience'] . '</saml:Audience>'
            . '</saml:AudienceRestriction></saml:Conditions>'
            . '<saml:AuthnStatement AuthnInstant="' . $now . '" SessionIndex="' . $v['assertionId'] . '">'
            . '<saml:AuthnContext>'
            . '<saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL2</saml:AuthnContextClassRef>'
            . '</saml:AuthnContext></saml:AuthnStatement>'
            . '<saml:AttributeStatement>'
            . '<saml:Attribute Name="fiscalNumber"><saml:AttributeValue>' . $attrValue
            . '</saml:AttributeValue></saml:Attribute>'
            . '</saml:AttributeStatement>'
            . '</saml:Assertion>';

        $signed = SignatureUtils::signXml(
            $assertion,
            ['sp_key_file' => self::$idpKey, 'sp_cert_file' => self::$idpCert]
        );
        // signXml returns a full document; drop the XML declaration so the result
        // can be embedded inside a <samlp:Response>.
        return preg_replace('/^<\?xml[^>]*\?>\s*/', '', $signed);
    }

    private function wrapInResponse(string $body): string
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        return '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response0123456789"'
            . ' Version="2.0" IssueInstant="' . $now . '" InResponseTo="' . self::$requestId . '"'
            . ' Destination="' . self::$acsUrl . '">'
            . '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
            . self::$idpEntityId . '</saml:Issuer>'
            . '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            . $body
            . '</samlp:Response>';
    }

    private function authenticate(string $responseXml): bool
    {
        // Build the Sp first: its constructor may call session_start(), which
        // would reset $_SESSION. Populating the session afterwards keeps it.
        $sp = new Italia\Spid\Sp(self::$settings, null, false);
        $this->resetSession();
        $_POST['SAMLResponse'] = base64_encode($responseXml);
        try {
            return $sp->isAuthenticated();
        } finally {
            unset($_POST['SAMLResponse']);
        }
    }

    // ---------------------------------------------------------------------
    // Baseline: an honestly signed response must be accepted (no regression).
    // ---------------------------------------------------------------------
    public function testGenuineSignedResponseIsAccepted(): void
    {
        $response = $this->wrapInResponse($this->signedAssertion('REAL-USER-FISCAL-CODE'));

        $this->assertTrue($this->authenticate($response));
        $this->assertSame(
            'REAL-USER-FISCAL-CODE',
            $_SESSION['spidSession']['attributes']['fiscalNumber'],
            'The session must carry the attributes of the signed assertion'
        );
    }

    // ---------------------------------------------------------------------
    // The core attack from the bulletin: a forged, unsigned assertion placed
    // before the genuine signed one. Must be rejected, and must NOT leak the
    // attacker identity into the session.
    // ---------------------------------------------------------------------
    public function testForgedAssertionBeforeSignedOneIsRejected(): void
    {
        $forged = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            . ' ID="_forged" Version="2.0" IssueInstant="' . gmdate('Y-m-d\TH:i:s\Z') . '">'
            . '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
            . self::$idpEntityId . '</saml:Issuer>'
            . '<saml:AttributeStatement><saml:Attribute Name="fiscalNumber">'
            . '<saml:AttributeValue>ATTACKER-ADMIN</saml:AttributeValue></saml:Attribute>'
            . '</saml:AttributeStatement></saml:Assertion>';

        $response = $this->wrapInResponse($forged . $this->signedAssertion('REAL-USER-FISCAL-CODE'));

        $this->expectException(\Exception::class);
        try {
            $this->authenticate($response);
        } catch (\Exception $e) {
            $this->assertArrayNotHasKey('spidSession', $_SESSION, 'No session must be created for a wrapped response');
            throw $e;
        }
    }

    // ---------------------------------------------------------------------
    // Wrapping variant: exactly one signed assertion, but a forged
    // AttributeStatement is added at the response level, outside the assertion.
    // item(0) would otherwise read it instead of the signed one.
    // ---------------------------------------------------------------------
    public function testForgedAttributeStatementOutsideAssertionIsRejected(): void
    {
        $forgedAttrs = '<saml:AttributeStatement><saml:Attribute Name="fiscalNumber">'
            . '<saml:AttributeValue>ATTACKER-ADMIN</saml:AttributeValue></saml:Attribute>'
            . '</saml:AttributeStatement>';

        $response = $this->wrapInResponse($forgedAttrs . $this->signedAssertion('REAL-USER-FISCAL-CODE'));

        $this->expectException(\Exception::class);
        $this->authenticate($response);
    }

    // ---------------------------------------------------------------------
    // Tampering with the signed assertion content must break the signature.
    // ---------------------------------------------------------------------
    public function testTamperedSignedAssertionIsRejected(): void
    {
        $signed = $this->signedAssertion('REAL-USER-FISCAL-CODE');
        $tampered = str_replace('REAL-USER-FISCAL-CODE', 'ATTACKER-ADMIN', $signed);
        $response = $this->wrapInResponse($tampered);

        $this->expectException(\Exception::class);
        $this->authenticate($response);
    }

    // ---------------------------------------------------------------------
    // An assertion signed by a different (attacker) key must be rejected: its
    // embedded certificate does not match the trusted IdP certificate.
    // ---------------------------------------------------------------------
    public function testAssertionSignedByUntrustedKeyIsRejected(): void
    {
        $rogue = SignatureUtils::generateKeyCert([
            'sp_org_name' => 'rogue',
            'sp_org_display_name' => 'rogue',
            'sp_key_cert_values' => [
                'countryName' => 'IT',
                'stateOrProvinceName' => 'Rome',
                'localityName' => 'Rome',
                'commonName' => 'rogue.example.com',
                'emailAddress' => 'rogue@example.com',
            ],
        ]);
        $rogueKey = self::$dir . '/rogue.key';
        $rogueCert = self::$dir . '/rogue.crt';
        file_put_contents($rogueKey, $rogue['key']);
        file_put_contents($rogueCert, $rogue['cert']);

        $now = gmdate('Y-m-d\TH:i:s\Z');
        $later = gmdate('Y-m-d\TH:i:s\Z', time() + 3600);
        $assertion = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            . ' ID="_rogue" Version="2.0" IssueInstant="' . $now . '">'
            . '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
            . self::$idpEntityId . '</saml:Issuer>'
            . '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"'
            . ' NameQualifier="' . self::$idpEntityId . '">_x</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData InResponseTo="' . self::$requestId . '"'
            . ' NotOnOrAfter="' . $later . '" Recipient="' . self::$acsUrl . '"/>'
            . '</saml:SubjectConfirmation></saml:Subject>'
            . '<saml:Conditions NotBefore="' . $now . '" NotOnOrAfter="' . $later . '">'
            . '<saml:AudienceRestriction><saml:Audience>' . self::$spEntityId . '</saml:Audience>'
            . '</saml:AudienceRestriction></saml:Conditions>'
            . '<saml:AuthnStatement AuthnInstant="' . $now . '" SessionIndex="_rogue">'
            . '<saml:AuthnContext><saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL2'
            . '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
            . '<saml:AttributeStatement><saml:Attribute Name="fiscalNumber">'
            . '<saml:AttributeValue>ATTACKER-ADMIN</saml:AttributeValue></saml:Attribute>'
            . '</saml:AttributeStatement></saml:Assertion>';
        $signed = preg_replace(
            '/^<\?xml[^>]*\?>\s*/',
            '',
            SignatureUtils::signXml($assertion, ['sp_key_file' => $rogueKey, 'sp_cert_file' => $rogueCert])
        );

        $response = $this->wrapInResponse($signed);

        $this->expectException(\Exception::class);
        $this->authenticate($response);
    }
}
