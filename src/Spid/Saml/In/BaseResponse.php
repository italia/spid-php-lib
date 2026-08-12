<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Saml\SignatureUtils;
use Italia\Spid\Spid\Saml;

/*
* Generates the proper response object at runtime by reading the input XML.
* Validates the response and the signature
* Specific response may complete other tasks upon succesful validation
* such as creating a login session for Response, or destroying the session
* for Logout resposnes.

* The only case in which a Request is validated instead of a response is
* for Idp Initiated Logout. In this case the input is not a response to a requese
* to a request sent by the SP, but rather a request started by the Idp
*/
class BaseResponse
{
    const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
    const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
    const NS_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#';

    const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    // Signature algorithms accepted on an incoming HTTP-Redirect query string.
    const REDIRECT_SIGNATURE_ALGOS = [
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => OPENSSL_ALGO_SHA256,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => OPENSSL_ALGO_SHA384,
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => OPENSSL_ALGO_SHA512,
    ];

    private $response;
    private $xml;
    private $root;

    // Name of the HTTP parameter the message was read from, and whether it
    // arrived through the HTTP-Redirect binding: the Redirect binding signs the
    // query string instead of the XML, so the two need different verification.
    private $messageParam;
    private $isRedirect = false;

    public function __construct(?Saml $saml = null)
    {
        // An IdP initiated LogoutRequest travels in SAMLRequest, everything else
        // in SAMLResponse. Ignoring SAMLRequest, as this used to, left the IdP
        // initiated logout flow unreachable through its normal parameter.
        foreach (['SAMLResponse', 'SAMLRequest'] as $param) {
            if (isset($_GET) && isset($_GET[$param])) {
                $this->messageParam = $param;
                $this->isRedirect = true;
                break;
            }
            if (isset($_POST) && isset($_POST[$param])) {
                $this->messageParam = $param;
                break;
            }
        }
        if (is_null($this->messageParam)) {
            return;
        }

        $encoded = $this->isRedirect ? $_GET[$this->messageParam] : $_POST[$this->messageParam];
        $decoded = base64_decode($encoded, true);
        if ($decoded === false || $decoded === '') {
            throw new \Exception('No valid response found');
        }
        if ($this->isRedirect) {
            $decoded = @gzinflate($decoded);
            if ($decoded === false || $decoded === '') {
                throw new \Exception('No valid response found');
            }
        }

        $this->xml = new \DOMDocument();
        // LIBXML_NONET keeps libxml from reaching the network while parsing.
        if (@$this->xml->loadXML($decoded, LIBXML_NONET) !== true) {
            throw new \Exception('No valid response found');
        }

        // The message is the root of the document, not merely the first protocol
        // element found somewhere inside it. Deciding the message type from a
        // nested element would let an attacker wrap the real message in an
        // envelope of their own and have the two read differently.
        $rootElement = $this->xml->documentElement;
        if (is_null($rootElement) || $rootElement->namespaceURI !== self::NS_SAMLP) {
            throw new \Exception('No valid response found');
        }
        $this->root = $rootElement->localName;

        if ($this->messageParam == 'SAMLRequest' && $this->root != 'LogoutRequest') {
            throw new \Exception('No valid response found');
        }

        switch ($this->root) {
            case 'Response':
                // When reloading the acs page, POST data is sent again even if login is completed
                // If login session already exists exit without checking the response again
                if (isset($_SESSION['spidSession'])) {
                    return;
                }
                if (is_null($saml)) {
                    return;
                }
                $this->response = new Response($saml);
                break;
            case 'LogoutResponse':
                $this->response = new LogoutResponse();
                break;
            case 'LogoutRequest':
                if (is_null($saml)) {
                    return;
                }
                $this->response = new LogoutRequest($saml);
                break;
            default:
                throw new \Exception('No valid response found');
                break;
        }
    }

    public function validate($cert) : bool
    {
        if (is_null($this->response)) {
            return true;
        }

        // Exactly one protocol element of the expected type, and it has to be the
        // root: everything below reaches for elements by name, so a second one
        // would be a place to hide a forged copy.
        $roots = $this->xml->getElementsByTagNameNS(self::NS_SAMLP, $this->root);
        if ($roots->length != 1 || !$roots->item(0)->isSameNode($this->xml->documentElement)) {
            throw new \Exception("Invalid Response. Exactly one " . $this->root .
                " element is required, as the root of the document");
        }

        $assertions = $this->xml->getElementsByTagNameNS(self::NS_SAML, 'Assertion');
        // A SPID response carries exactly one assertion. Refusing anything else
        // removes the room a signature wrapping attack needs to smuggle a forged,
        // unsigned assertion next to the genuine signed one (CWE-347, CWE-349,
        // CWE-290).
        if ($assertions->length > 1) {
            throw new \Exception("Invalid Response. A Response must not contain more than one Assertion");
        }
        $assertion = $assertions->item(0);

        // What has to be signed is decided by the type of message, NOT by what the
        // message happens to contain. Deriving the requirement from the presence of
        // an assertion, as this used to, meant an attacker could opt out of the
        // signature check entirely just by sending a successful Response with no
        // assertion at all, and the identity was then read from the unsigned
        // document (CWE-347, CWE-290).
        $needsSignedAssertion = $this->root == 'Response' && $this->isSuccess();

        if ($needsSignedAssertion && is_null($assertion)) {
            throw new \Exception("Invalid Response. A successful Response must contain exactly one Assertion");
        }
        if (!$needsSignedAssertion && !is_null($assertion)) {
            throw new \Exception("Invalid Response. Unexpected Assertion in a " . $this->root);
        }

        list($responseSignature, $assertionSignature) = $this->locateSignatures($assertion);

        if ($needsSignedAssertion && is_null($assertionSignature)) {
            throw new \Exception("Invalid Response. The Assertion must be signed");
        }

        // Logout messages carry no assertion, so their own integrity is all there
        // is: require it explicitly instead of accepting whatever turns up. Over
        // the Redirect binding the signature covers the query string rather than
        // the XML, so the two bindings are verified differently.
        if ($this->root == 'LogoutResponse' || $this->root == 'LogoutRequest') {
            if ($this->isRedirect) {
                $this->validateQuerySignature($cert);
            } elseif (is_null($responseSignature)) {
                throw new \Exception("Invalid Response. The " . $this->root . " must be signed");
            }
        }

        foreach ([$responseSignature, $assertionSignature] as $signature) {
            if (!is_null($signature) && !SignatureUtils::validateXmlSignature($signature, $cert)) {
                throw new \Exception("Invalid Response. Signature validation failed");
            }
        }

        // Defence in depth against signature wrapping: every identity-bearing
        // element that the downstream validation and the attribute extraction
        // read with getElementsByTagName(...)->item(0) MUST live inside the
        // assertion that was just cryptographically validated. If any such
        // element also appears outside it, item(0) could return the forged copy
        // instead of the signed one, so the response is rejected.
        if (!is_null($assertion)) {
            $this->assertNoElementsOutsideAssertion($assertion);
        }

        return $this->response->validate($this->xml, $assertion);
    }

    // True when the message reports urn:oasis:names:tc:SAML:2.0:status:Success.
    // The Status is read as a direct child of the root, because that is the only
    // place where it belongs and the only one that cannot be shadowed.
    private function isSuccess() : bool
    {
        foreach ($this->xml->documentElement->childNodes as $child) {
            if (!($child instanceof \DOMElement)) {
                continue;
            }
            if ($child->localName != 'Status' || $child->namespaceURI !== self::NS_SAMLP) {
                continue;
            }
            foreach ($child->childNodes as $statusChild) {
                if (!($statusChild instanceof \DOMElement)) {
                    continue;
                }
                if ($statusChild->localName != 'StatusCode' || $statusChild->namespaceURI !== self::NS_SAMLP) {
                    continue;
                }
                return $statusChild->getAttribute('Value') === self::STATUS_SUCCESS;
            }
        }
        return false;
    }

    // Splits the signatures found in the document into the one protecting the
    // root and the one protecting the assertion, refusing any other placement.
    private function locateSignatures(?\DOMElement $assertion) : array
    {
        $responseSignature = null;
        $assertionSignature = null;

        $signatures = $this->xml->getElementsByTagNameNS(self::NS_SIGNATURE, 'Signature');
        foreach ($signatures as $item) {
            $parent = $item->parentNode;
            // Only a signature directly protecting the assertion or the protocol
            // root is meaningful; one placed anywhere else, or a second signature
            // on the same element, is a wrapping attempt.
            if (!is_null($assertion) && $parent->isSameNode($assertion)) {
                if (!is_null($assertionSignature)) {
                    throw new \Exception("Invalid Response. The Assertion must not carry more than one signature");
                }
                $assertionSignature = $item;
            } elseif ($parent->isSameNode($this->xml->documentElement)) {
                if (!is_null($responseSignature)) {
                    throw new \Exception("Invalid Response. The " . $this->root .
                        " must not carry more than one signature");
                }
                $responseSignature = $item;
            } else {
                throw new \Exception("Invalid Response. Signature found in an unexpected position");
            }
        }
        return [$responseSignature, $assertionSignature];
    }

    // Verifies the HTTP-Redirect binding signature, which covers the exact
    // sequence of query parameters rather than the XML document.
    private function validateQuerySignature($cert)
    {
        if (!isset($_GET['Signature']) || !isset($_GET['SigAlg'])) {
            throw new \Exception("Invalid Response. Missing Signature or SigAlg on the query string");
        }
        $this->assertNoDuplicateQueryParameters();

        $sigAlg = $_GET['SigAlg'];
        if (!array_key_exists($sigAlg, self::REDIRECT_SIGNATURE_ALGOS)) {
            throw new \Exception("Invalid Response. Signature algorithm " . $sigAlg . " is not accepted");
        }

        $signed = $this->messageParam . '=' . rawurlencode($_GET[$this->messageParam]);
        if (isset($_GET['RelayState'])) {
            $signed .= '&RelayState=' . rawurlencode($_GET['RelayState']);
        }
        $signed .= '&SigAlg=' . rawurlencode($sigAlg);

        $signature = base64_decode($_GET['Signature'], true);
        if ($signature === false) {
            throw new \Exception("Invalid Response. Malformed Signature on the query string");
        }
        $key = @openssl_pkey_get_public($cert);
        if ($key === false) {
            throw new \Exception("Invalid Response. The Identity Provider certificate could not be read");
        }
        if (openssl_verify($signed, $signature, $key, self::REDIRECT_SIGNATURE_ALGOS[$sigAlg]) !== 1) {
            throw new \Exception("Invalid Response. Query string signature validation failed");
        }
    }

    // PHP keeps only the last occurrence of a repeated query parameter, so a
    // duplicate would let the signature be verified over a different value than
    // the one the rest of the code reads.
    private function assertNoDuplicateQueryParameters()
    {
        if (!isset($_SERVER['QUERY_STRING']) || $_SERVER['QUERY_STRING'] === '') {
            return;
        }
        $seen = [];
        foreach (explode('&', $_SERVER['QUERY_STRING']) as $pair) {
            if ($pair === '') {
                continue;
            }
            $name = rawurldecode(explode('=', $pair, 2)[0]);
            if (isset($seen[$name])) {
                throw new \Exception("Invalid Response. Duplicate " . $name . " parameter on the query string");
            }
            $seen[$name] = true;
        }
    }

    // Rejects the response if any identity-bearing element exists outside the
    // signed assertion. The counts are taken with getElementsByTagName(), i.e.
    // by local name across every namespace, exactly like the code that later
    // reads these elements, so a forged copy in a foreign namespace cannot slip
    // through either.
    private function assertNoElementsOutsideAssertion(\DOMElement $assertion)
    {
        $scopedTags = [
            'Subject', 'NameID', 'SubjectConfirmation', 'SubjectConfirmationData',
            'Conditions', 'AudienceRestriction', 'Audience',
            'AuthnStatement', 'AuthnContextClassRef',
            'AttributeStatement', 'Attribute', 'AttributeValue',
        ];
        foreach ($scopedTags as $tag) {
            $inDocument = $this->xml->getElementsByTagName($tag)->length;
            $inAssertion = $assertion->getElementsByTagName($tag)->length;
            if ($inDocument !== $inAssertion) {
                throw new \Exception(
                    "Invalid Response. Unexpected " . $tag . " element found outside the signed assertion"
                );
            }
        }
    }
}
