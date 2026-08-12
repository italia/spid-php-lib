<?php

declare(strict_types=1);

use Italia\Spid\Spid\Saml\SignatureUtils;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SamlFixture.php';

/**
 * Regression tests for the authentication bypass reported against
 * f5899ebcac646506c80a078fa2f415ed59605952, plus the SPID level and session
 * fixation weaknesses found alongside it.
 *
 * The bypass: the library required a signature only when the response happened to
 * contain an Assertion, so a Response with StatusCode=Success carrying no
 * Assertion and no signature at all skipped every identity check, and the session
 * was then built from elements read anywhere in the unsigned document. No SPID
 * identity, no assertion, no key material were needed (CWE-347, CWE-290).
 */
final class ResponseSecurityTest extends TestCase
{
    /** @var SamlFixture */
    private static $f;

    public static function setUpBeforeClass(): void
    {
        self::$f = new SamlFixture('spid_response_sec');
        // Start the session up front so populating $_SESSION in the individual
        // tests is not wiped by the session_start() the first Sp would trigger.
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$f->cleanUp();
    }

    protected function tearDown(): void
    {
        // Do not leak session or request state into the other test classes.
        $_SESSION = [];
        $_GET = [];
        unset($_POST['SAMLResponse'], $_POST['SAMLRequest']);
    }

    private function session(array $overrides = []): array
    {
        return self::$f->loginSession(array_merge([
            'requestedLevel' => 2,
            'requestedComparison' => 'exact',
        ], $overrides));
    }

    // -----------------------------------------------------------------
    // Baseline: the honest response still works.
    // -----------------------------------------------------------------
    public function testGenuineSignedResponseIsAccepted(): void
    {
        $response = self::$f->response(self::$f->signedAssertion());

        $this->assertTrue(self::$f->post($this->session(), $response));
        $this->assertSame(
            'REAL-USER-FISCAL-CODE',
            $_SESSION['spidSession']['attributes']['fiscalNumber'],
            'The session must carry the attributes of the signed assertion'
        );
        $this->assertSame(2, $_SESSION['spidSession']['level']);
    }

    // -----------------------------------------------------------------
    // The reported bypass, in the exact shape of the report's PoC.
    // -----------------------------------------------------------------
    public function testSuccessResponseWithoutAssertionIsRejected(): void
    {
        $forged = self::$f->response(
            '<saml:AttributeStatement>'
            . '<saml:Attribute Name="fiscalNumber">'
            . '<saml:AttributeValue>ATTACKER-OWNED</saml:AttributeValue></saml:Attribute>'
            . '</saml:AttributeStatement>'
            . '<saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL3</saml:AuthnContextClassRef>'
        );

        $this->expectException(\Exception::class);
        try {
            self::$f->post($this->session(), $forged);
        } catch (\Exception $e) {
            $this->assertArrayNotHasKey(
                'spidSession',
                $_SESSION,
                'A response with no assertion must never produce a session'
            );
            throw $e;
        }
    }

    public function testSuccessResponseWithUnsignedAssertionIsRejected(): void
    {
        $response = self::$f->response(self::$f->assertionXml(['fiscalNumber' => 'ATTACKER-OWNED']));

        $this->expectException(\Exception::class);
        self::$f->post($this->session(), $response);
    }

    // A signature on the Response root does not stand in for the assertion
    // signature: the policy requires the assertion itself to be signed.
    public function testResponseSignedOnlyOnTheRootIsRejected(): void
    {
        $response = self::$f->sign(
            self::$f->response(self::$f->assertionXml(['fiscalNumber' => 'ATTACKER-OWNED']))
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->session(), $response);
    }

    // -----------------------------------------------------------------
    // Failure responses: no assertion is expected, and no session may appear.
    // -----------------------------------------------------------------
    public function testErrorResponseWithoutAssertionCreatesNoSession(): void
    {
        $response = self::$f->response('', ['status' => 'urn:oasis:names:tc:SAML:2.0:status:Requester']);

        try {
            self::$f->post($this->session(), $response);
            $this->fail('A non successful response must be refused');
        } catch (\Exception $e) {
            $this->assertStringContainsString('StatusCode is not Success', $e->getMessage());
        }
        $this->assertArrayNotHasKey('spidSession', $_SESSION);
    }

    public function testErrorResponseCarryingAnAssertionIsRejected(): void
    {
        $response = self::$f->response(
            self::$f->signedAssertion(),
            ['status' => 'urn:oasis:names:tc:SAML:2.0:status:Requester']
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->session(), $response);
    }

    // -----------------------------------------------------------------
    // Wrapping variants that must stay closed.
    // -----------------------------------------------------------------
    public function testHomonymElementInForeignNamespaceIsRejected(): void
    {
        // Same local name, different namespace, placed outside the assertion:
        // getElementsByTagName() ignores the namespace, so item(0) could pick it.
        $response = self::$f->response(
            '<evil:AttributeStatement xmlns:evil="urn:attacker">'
            . '<evil:Attribute Name="fiscalNumber">'
            . '<evil:AttributeValue>ATTACKER-OWNED</evil:AttributeValue></evil:Attribute>'
            . '</evil:AttributeStatement>'
            . self::$f->signedAssertion()
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->session(), $response);
    }

    public function testNestedResponseInsideAnEnvelopeIsRejected(): void
    {
        $inner = self::$f->response(self::$f->signedAssertion());
        $enveloped = '<wrapper xmlns="urn:attacker">'
            . preg_replace('/^<\?xml[^>]*\?>\s*/', '', $inner)
            . '</wrapper>';

        $this->expectException(\Exception::class);
        self::$f->post($this->session(), $enveloped);
    }

    public function testTwoAssertionsAreRejected(): void
    {
        $response = self::$f->response(
            self::$f->signedAssertion() .
            self::$f->signedAssertion(['assertionId' => '_second', 'fiscalNumber' => 'ATTACKER-OWNED'])
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->session(), $response);
    }

    // -----------------------------------------------------------------
    // An absent signature must never read as a verified one.
    // -----------------------------------------------------------------
    public function testValidateXmlSignatureRefusesAnAbsentSignature(): void
    {
        $this->assertFalse(
            SignatureUtils::validateXmlSignature(null, file_get_contents(self::$f->idpCert)),
            'A null signature node must not validate'
        );
    }

    // -----------------------------------------------------------------
    // SPID level: the asserted level must be a real one and must satisfy the
    // level the Service Provider asked for.
    // -----------------------------------------------------------------
    public function testLowerLevelThanRequestedIsRejected(): void
    {
        $response = self::$f->response(
            self::$f->signedAssertion(['authnContextClassRef' => 'https://www.spid.gov.it/SpidL1'])
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->session(['requestedLevel' => 2]), $response);
    }

    public function testLevel2AgainstRequestedLevel3IsRejected(): void
    {
        $response = self::$f->response(self::$f->signedAssertion());

        $this->expectException(\Exception::class);
        self::$f->post($this->session(['requestedLevel' => 3]), $response);
    }

    public function testUnknownAuthnContextClassRefEndingInTheRightDigitIsRejected(): void
    {
        $response = self::$f->response(
            self::$f->signedAssertion(['authnContextClassRef' => 'https://attacker.example/SpidL2'])
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->session(), $response);
    }

    public function testMultipleAuthnContextClassRefIsRejected(): void
    {
        $response = self::$f->response(self::$f->signedAssertion([
            'extraAuthnContextClassRef' =>
                '<saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL3</saml:AuthnContextClassRef>',
        ]));

        $this->expectException(\Exception::class);
        self::$f->post($this->session(['requestedLevel' => 3]), $response);
    }

    public function testMinimumComparisonAcceptsAHigherLevel(): void
    {
        $response = self::$f->response(
            self::$f->signedAssertion(['authnContextClassRef' => 'https://www.spid.gov.it/SpidL3'])
        );

        $this->assertTrue(
            self::$f->post($this->session(['requestedLevel' => 2, 'requestedComparison' => 'minimum']), $response)
        );
        $this->assertSame(3, $_SESSION['spidSession']['level']);
    }

    public function testBetterComparisonRejectsAnEqualLevel(): void
    {
        $response = self::$f->response(self::$f->signedAssertion());

        $this->expectException(\Exception::class);
        self::$f->post($this->session(['requestedLevel' => 2, 'requestedComparison' => 'better']), $response);
    }

    public function testMaximumComparisonRejectsAHigherLevel(): void
    {
        $response = self::$f->response(
            self::$f->signedAssertion(['authnContextClassRef' => 'https://www.spid.gov.it/SpidL3'])
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->session(['requestedLevel' => 2, 'requestedComparison' => 'maximum']), $response);
    }

    // -----------------------------------------------------------------
    // Session fixation: the pre-login identifier must not carry the
    // authenticated state.
    // -----------------------------------------------------------------
    public function testSessionIdIsRegeneratedOnLogin(): void
    {
        $response = self::$f->response(self::$f->signedAssertion());

        $before = session_id();
        $this->assertNotSame('', $before, 'the test needs an active session');

        $this->assertTrue(self::$f->post($this->session(), $response));

        $this->assertNotSame($before, session_id(), 'the session id must change when the login completes');
        $this->assertArrayHasKey('spidSession', $_SESSION);
    }
}
