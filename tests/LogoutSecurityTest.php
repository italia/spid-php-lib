<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SamlFixture.php';

/**
 * Regression tests for the incomplete integrity verification of the logout
 * messages reported against f5899ebcac646506c80a078fa2f415ed59605952.
 *
 * A LogoutResponse carrying no signature at all reached the end of validation and
 * terminated the session as long as the attacker knew the correlation values, and
 * the HTTP-Redirect binding never verified the SigAlg/Signature pair it receives.
 * An Identity Provider initiated LogoutRequest was unreachable through its normal
 * SAMLRequest parameter, and its validation used a variable before assigning it.
 */
final class LogoutSecurityTest extends TestCase
{
    /** @var SamlFixture */
    private static $f;
    private static $rogueKey;

    public static function setUpBeforeClass(): void
    {
        self::$f = new SamlFixture('spid_logout_sec');
        $rogue = SamlFixture::keyPair('rogue.example.com');
        self::$rogueKey = self::$f->dir . '/rogue.key';
        file_put_contents(self::$rogueKey, $rogue['key']);

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
        $_SESSION = [];
        $_GET = [];
        unset($_POST['SAMLResponse'], $_POST['SAMLRequest'], $_SERVER['QUERY_STRING']);
    }

    // Session as it is right after the SP sent its LogoutRequest.
    private function logoutSession(): array
    {
        return [
            'idpName' => 'idp',
            'RequestID' => self::$f->requestId,
            'sloUrl' => self::$f->sloUrl,
            'idpEntityId' => self::$f->idpEntityId,
            'spidSession' => [
                'sessionID' => self::$f->requestId,
                'idp' => 'idp',
                'idpEntityID' => self::$f->idpEntityId,
                'level' => 2,
                'attributes' => ['fiscalNumber' => 'REAL-USER-FISCAL-CODE'],
            ],
        ];
    }

    // -----------------------------------------------------------------
    // POST binding: the XML signature is what authenticates the message.
    // -----------------------------------------------------------------
    public function testSignedLogoutResponseTerminatesTheSession(): void
    {
        $signed = self::$f->sign(self::$f->logoutResponse());

        $this->assertFalse(self::$f->post($this->logoutSession(), $signed));
        $this->assertArrayNotHasKey('spidSession', $_SESSION, 'the session must be gone after a logout');
    }

    public function testUnsignedLogoutResponseIsRejected(): void
    {
        $this->expectException(\Exception::class);
        try {
            self::$f->post($this->logoutSession(), self::$f->logoutResponse());
        } catch (\Exception $e) {
            $this->assertArrayHasKey(
                'spidSession',
                $_SESSION,
                'an unauthenticated logout must not touch the session'
            );
            throw $e;
        }
    }

    public function testLogoutResponseSignedByAnotherKeyIsRejected(): void
    {
        $rogueCert = self::$f->dir . '/rogue.crt';
        $kp = SamlFixture::keyPair('rogue2.example.com');
        file_put_contents(self::$f->dir . '/rogue2.key', $kp['key']);
        file_put_contents($rogueCert, $kp['cert']);

        $signed = self::$f->sign(
            self::$f->logoutResponse(),
            self::$f->dir . '/rogue2.key',
            $rogueCert
        );

        $this->expectException(\Exception::class);
        self::$f->post($this->logoutSession(), $signed);
    }

    // -----------------------------------------------------------------
    // Redirect binding: the signature covers the query string.
    // -----------------------------------------------------------------
    public function testRedirectLogoutResponseWithValidQuerySignatureIsAccepted(): void
    {
        $this->assertFalse(self::$f->redirect(
            $this->logoutSession(),
            self::$f->logoutResponse(),
            'SAMLResponse',
            self::$f->idpKey
        ));
        $this->assertArrayNotHasKey('spidSession', $_SESSION);
    }

    public function testRedirectLogoutResponseWithoutSignatureIsRejected(): void
    {
        $this->expectException(\Exception::class);
        self::$f->redirect($this->logoutSession(), self::$f->logoutResponse());
    }

    public function testRedirectLogoutResponseSignedByAnotherKeyIsRejected(): void
    {
        $this->expectException(\Exception::class);
        self::$f->redirect(
            $this->logoutSession(),
            self::$f->logoutResponse(),
            'SAMLResponse',
            self::$rogueKey
        );
    }

    public function testRedirectLogoutResponseWithDisallowedAlgorithmIsRejected(): void
    {
        $this->expectException(\Exception::class);
        self::$f->redirect(
            $this->logoutSession(),
            self::$f->logoutResponse(),
            'SAMLResponse',
            self::$f->idpKey,
            ['SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1']
        );
    }

    public function testRedirectLogoutResponseWithAlteredSignatureIsRejected(): void
    {
        $this->expectException(\Exception::class);
        self::$f->redirect(
            $this->logoutSession(),
            self::$f->logoutResponse(),
            'SAMLResponse',
            self::$f->idpKey,
            ['Signature' => base64_encode('not a signature')]
        );
    }

    public function testRedirectLogoutResponseWithDuplicateParametersIsRejected(): void
    {
        $this->expectException(\Exception::class);
        self::$f->redirect(
            $this->logoutSession(),
            self::$f->logoutResponse(),
            'SAMLResponse',
            self::$f->idpKey,
            ['QUERY_STRING' => 'SAMLResponse=a&SAMLResponse=b&SigAlg=x&Signature=y']
        );
    }

    // -----------------------------------------------------------------
    // Identity Provider initiated logout, which arrives in SAMLRequest.
    // -----------------------------------------------------------------
    public function testSignedLogoutRequestOnSamlRequestIsProcessed(): void
    {
        $signed = self::$f->sign(self::$f->logoutRequest());

        // isAuthenticated() answers false and the library replies to the Identity
        // Provider with its own LogoutResponse, clearing the local session.
        $this->assertFalse(self::$f->post($this->logoutSession(), $signed, 'SAMLRequest'));
        $this->assertArrayNotHasKey('spidSession', $_SESSION);
    }

    public function testUnsignedLogoutRequestIsRejected(): void
    {
        $this->expectException(\Exception::class);
        try {
            self::$f->post($this->logoutSession(), self::$f->logoutRequest(), 'SAMLRequest');
        } catch (\Exception $e) {
            $this->assertArrayHasKey('spidSession', $_SESSION);
            throw $e;
        }
    }

    public function testLogoutRequestForAnotherSessionIsRejected(): void
    {
        $signed = self::$f->sign(self::$f->logoutRequest(['sessionIndex' => '_someone-elses-session']));

        $this->expectException(\Exception::class);
        self::$f->post($this->logoutSession(), $signed, 'SAMLRequest');
    }

    public function testLogoutRequestWithWrongDestinationIsRejected(): void
    {
        $signed = self::$f->sign(self::$f->logoutRequest(['destination' => 'https://attacker.example/']));

        $this->expectException(\Exception::class);
        self::$f->post($this->logoutSession(), $signed, 'SAMLRequest');
    }

    // A Response must not be accepted through the parameter reserved for requests.
    public function testResponseOnSamlRequestIsRejected(): void
    {
        $response = self::$f->response(self::$f->signedAssertion());

        $this->expectException(\Exception::class);
        self::$f->post($this->logoutSession(), $response, 'SAMLRequest');
    }
}
