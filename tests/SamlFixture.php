<?php

declare(strict_types=1);

use Italia\Spid\Spid\Saml\SignatureUtils;

/**
 * Shared fixture for the security regression tests: a throwaway Identity Provider
 * with its own key pair and metadata, plus builders for the SAML messages the
 * tests need to forge.
 *
 * Not a test case, and deliberately not named *Test.php so PHPUnit does not try
 * to collect it. Test files pull it in with require_once.
 */
class SamlFixture
{
    public $dir;
    public $idpKey;
    public $idpCert;
    public $settings;

    public $idpEntityId = 'https://idp.example.com/';
    public $spEntityId = 'https://sp.example.com/';
    public $acsUrl = 'https://sp.example.com/acs';
    public $sloUrl = 'https://sp.example.com/slo';
    public $requestId = '_request0123456789abcdef';

    public function __construct(string $prefix)
    {
        $this->dir = sys_get_temp_dir() . '/' . $prefix . '_' . getmypid();
        @mkdir($this->dir);
        @mkdir($this->dir . '/idp_metadata');

        $kc = self::keyPair('idp.example.com');
        $this->idpKey = $this->dir . '/idp.key';
        $this->idpCert = $this->dir . '/idp.crt';
        file_put_contents($this->idpKey, $kc['key']);
        file_put_contents($this->idpCert, $kc['cert']);

        file_put_contents(
            $this->dir . '/idp_metadata/idp.xml',
            $this->metadataFor($kc['cert'])
        );

        // A real Service Provider key pair, so the outgoing messages the library
        // builds during a logout round trip can actually be signed.
        $sp = self::keyPair('sp.example.com');
        file_put_contents($this->dir . '/sp.key', $sp['key']);
        file_put_contents($this->dir . '/sp.crt', $sp['cert']);

        $this->settings = [
            'sp_entityid' => $this->spEntityId,
            'sp_key_file' => $this->dir . '/sp.key',
            'sp_cert_file' => $this->dir . '/sp.crt',
            'sp_assertionconsumerservice' => [$this->acsUrl],
            'sp_singlelogoutservice' => [[$this->sloUrl, '']],
            'idp_metadata_folder' => $this->dir . '/idp_metadata/',
        ];
    }

    public static function keyPair(string $cn) : array
    {
        return SignatureUtils::generateKeyCert([
            'sp_org_name' => $cn,
            'sp_org_display_name' => $cn,
            'sp_key_cert_values' => [
                'countryName' => 'IT',
                'stateOrProvinceName' => 'Rome',
                'localityName' => 'Rome',
                'commonName' => $cn,
                'emailAddress' => 'info@' . $cn,
            ],
        ]);
    }

    public function metadataFor(string $cert) : string
    {
        $clean = str_replace(
            ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"],
            '',
            $cert
        );
        return '<?xml version="1.0"?>'
            . '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
            . ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="' . $this->idpEntityId . '">'
            . '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            . '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
            . $clean
            . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
            . '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
            . ' Location="' . $this->idpEntityId . 'slo"/>'
            . '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
            . ' Location="' . $this->idpEntityId . 'slo"/>'
            . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
            . ' Location="' . $this->idpEntityId . 'sso"/>'
            . '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
            . ' Location="' . $this->idpEntityId . 'sso"/>'
            . '</md:IDPSSODescriptor></md:EntityDescriptor>';
    }

    public function cleanUp()
    {
        foreach (['/idp_metadata/*', '/*'] as $pattern) {
            foreach (glob($this->dir . $pattern) ?: [] as $f) {
                if (is_link($f) || is_file($f)) {
                    @unlink($f);
                }
            }
        }
        foreach (glob($this->dir . '/*', GLOB_ONLYDIR) ?: [] as $d) {
            @rmdir($d);
        }
        @rmdir($this->dir . '/idp_metadata');
        @rmdir($this->dir);
    }

    // ------------------------------------------------------------------
    // Message builders
    // ------------------------------------------------------------------

    public function assertionXml(array $overrides = []) : string
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $later = gmdate('Y-m-d\TH:i:s\Z', time() + 3600);
        $v = array_merge([
            'assertionId' => '_assertion0123456789abcdef',
            'idpEntityId' => $this->idpEntityId,
            'requestId' => $this->requestId,
            'acsUrl' => $this->acsUrl,
            'audience' => $this->spEntityId,
            'fiscalNumber' => 'REAL-USER-FISCAL-CODE',
            'authnContextClassRef' => 'https://www.spid.gov.it/SpidL2',
            'extraAuthnContextClassRef' => '',
        ], $overrides);

        return '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
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
            . '<saml:AuthnContextClassRef>' . $v['authnContextClassRef'] . '</saml:AuthnContextClassRef>'
            . $v['extraAuthnContextClassRef']
            . '</saml:AuthnContext></saml:AuthnStatement>'
            . '<saml:AttributeStatement>'
            . '<saml:Attribute Name="fiscalNumber"><saml:AttributeValue>' . $v['fiscalNumber']
            . '</saml:AttributeValue></saml:Attribute>'
            . '</saml:AttributeStatement>'
            . '</saml:Assertion>';
    }

    // Signs $xml with the Identity Provider key (or with $key/$cert when given) and
    // strips the XML declaration so the result can be embedded in another document.
    public function sign(string $xml, ?string $key = null, ?string $cert = null) : string
    {
        $signed = SignatureUtils::signXml($xml, [
            'sp_key_file' => $key ?? $this->idpKey,
            'sp_cert_file' => $cert ?? $this->idpCert,
        ]);
        return preg_replace('/^<\?xml[^>]*\?>\s*/', '', $signed);
    }

    public function signedAssertion(array $overrides = []) : string
    {
        return $this->sign($this->assertionXml($overrides));
    }

    public function response(string $body, array $overrides = []) : string
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $v = array_merge([
            'status' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
            'responseId' => '_response0123456789',
            'requestId' => $this->requestId,
            'acsUrl' => $this->acsUrl,
            'idpEntityId' => $this->idpEntityId,
        ], $overrides);

        return '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . $v['responseId'] . '"'
            . ' Version="2.0" IssueInstant="' . $now . '" InResponseTo="' . $v['requestId'] . '"'
            . ' Destination="' . $v['acsUrl'] . '">'
            . '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
            . $v['idpEntityId'] . '</saml:Issuer>'
            . '<samlp:Status><samlp:StatusCode Value="' . $v['status'] . '"/></samlp:Status>'
            . $body
            . '</samlp:Response>';
    }

    public function logoutResponse(array $overrides = []) : string
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $v = array_merge([
            'status' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
            'id' => '_logoutresponse0123456789',
            'requestId' => $this->requestId,
            'destination' => $this->sloUrl,
            'idpEntityId' => $this->idpEntityId,
        ], $overrides);

        return '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . $v['id'] . '"'
            . ' Version="2.0" IssueInstant="' . $now . '" InResponseTo="' . $v['requestId'] . '"'
            . ' Destination="' . $v['destination'] . '">'
            . '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
            . $v['idpEntityId'] . '</saml:Issuer>'
            . '<samlp:Status><samlp:StatusCode Value="' . $v['status'] . '"/></samlp:Status>'
            . '</samlp:LogoutResponse>';
    }

    public function logoutRequest(array $overrides = []) : string
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $v = array_merge([
            'id' => '_logoutrequest0123456789',
            'destination' => $this->spEntityId,
            'idpEntityId' => $this->idpEntityId,
            'sessionIndex' => $this->requestId,
        ], $overrides);

        return '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . $v['id'] . '"'
            . ' Version="2.0" IssueInstant="' . $now . '" Destination="' . $v['destination'] . '">'
            . '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"'
            . ' NameQualifier="' . $v['idpEntityId'] . '">' . $v['idpEntityId'] . '</saml:Issuer>'
            . '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"'
            . ' NameQualifier="' . $v['idpEntityId'] . '">_transient-name-id</saml:NameID>'
            . '<samlp:SessionIndex>' . $v['sessionIndex'] . '</samlp:SessionIndex>'
            . '</samlp:LogoutRequest>';
    }

    // ------------------------------------------------------------------
    // Driving the library
    // ------------------------------------------------------------------

    // Seeds the session exactly as Idp::authnRequest would have, then hands the
    // message to the library through the ACS entry point.
    public function loginSession(array $overrides = []) : array
    {
        return array_merge([
            'idpName' => 'idp',
            'RequestID' => $this->requestId,
            'acsUrl' => $this->acsUrl,
            'idpEntityId' => $this->idpEntityId,
        ], $overrides);
    }

    public function post(array $session, string $xml, string $param = 'SAMLResponse') : bool
    {
        // Build the Sp first: its constructor may call session_start(), which would
        // reset $_SESSION. Populating the session afterwards keeps it.
        $sp = new Italia\Spid\Sp($this->settings, null, false);
        $_SESSION = $session;
        $_POST[$param] = base64_encode($xml);
        try {
            return $sp->isAuthenticated();
        } finally {
            unset($_POST[$param]);
        }
    }

    // Same, over the HTTP-Redirect binding, signing the query string with $key when
    // one is given. Returns the result of isAuthenticated().
    public function redirect(
        array $session,
        string $xml,
        string $param = 'SAMLResponse',
        ?string $key = null,
        array $tamper = []
    ) : bool {
        $sp = new Italia\Spid\Sp($this->settings, null, false);
        $_SESSION = $session;

        $message = base64_encode(gzdeflate($xml));
        $sigAlg = $tamper['SigAlg'] ?? 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

        $_GET = [$param => $message, 'SigAlg' => $sigAlg];
        if (isset($tamper['RelayState'])) {
            $_GET['RelayState'] = $tamper['RelayState'];
        }
        if (!is_null($key)) {
            $signed = $param . '=' . rawurlencode($message);
            if (isset($tamper['RelayState'])) {
                $signed .= '&RelayState=' . rawurlencode($tamper['RelayState']);
            }
            $signed .= '&SigAlg=' . rawurlencode($sigAlg);
            openssl_sign($signed, $raw, openssl_get_privatekey(file_get_contents($key)), OPENSSL_ALGO_SHA256);
            $_GET['Signature'] = $tamper['Signature'] ?? base64_encode($raw);
        }
        if (isset($tamper['QUERY_STRING'])) {
            $_SERVER['QUERY_STRING'] = $tamper['QUERY_STRING'];
        }
        try {
            return $sp->isAuthenticated();
        } finally {
            $_GET = [];
            unset($_SERVER['QUERY_STRING']);
        }
    }
}
