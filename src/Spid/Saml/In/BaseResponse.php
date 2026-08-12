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
    private $response;
    private $xml;
    private $root;

    public function __construct(?Saml $saml = null)
    {
        if ((!isset($_POST) || !isset($_POST['SAMLResponse'])) &&
            (!isset($_GET) || !isset($_GET['SAMLResponse']))
        ) {
            return;
        }
        $xmlString = isset($_GET['SAMLResponse']) ?
            gzinflate(base64_decode($_GET['SAMLResponse'])) :
            base64_decode($_POST['SAMLResponse']);
        $this->xml = new \DOMDocument();
        $this->xml->loadXML($xmlString);

        $ns_samlp = 'urn:oasis:names:tc:SAML:2.0:protocol';
        $this->root = $this->xml->getElementsByTagNameNS($ns_samlp, '*')->item(0)->localName;

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

        $ns_saml = 'urn:oasis:names:tc:SAML:2.0:assertion';
        $ns_samlp = 'urn:oasis:names:tc:SAML:2.0:protocol';
        $ns_signature = 'http://www.w3.org/2000/09/xmldsig#';

        $assertions = $this->xml->getElementsByTagNameNS($ns_saml, 'Assertion');
        $hasAssertion = $assertions->length > 0;

        // A SPID response carries exactly one assertion inside exactly one
        // protocol root. Refusing anything else removes the room a signature
        // wrapping attack needs to smuggle a forged, unsigned assertion next to
        // the genuine signed one (CWE-347, CWE-349, CWE-290).
        if ($assertions->length > 1) {
            throw new \Exception("Invalid Response. A Response must not contain more than one Assertion");
        }
        if ($this->xml->getElementsByTagNameNS($ns_samlp, $this->root)->length != 1) {
            throw new \Exception("Invalid Response. Exactly one " . $this->root . " element is required");
        }

        // SECURITY FIX (CRITICAL - full authentication bypass, finding #1):
        // Every check below this point is conditioned on $hasAssertion. Without
        // this check, a Response with StatusCode=Success but NO Assertion at
        // all (and therefore no signature requirement triggered below either)
        // skips every downstream check and still results in
        // Response::validate() creating an authenticated session. A successful
        // authentication Response must always carry exactly one Assertion.
        if ($this->root === 'Response') {
            $statusCodes = $this->xml->getElementsByTagNameNS($ns_samlp, 'StatusCode');
            $isSuccess = $statusCodes->length > 0 &&
                $statusCodes->item(0)->getAttribute('Value') === 'urn:oasis:names:tc:SAML:2.0:status:Success';
            if ($isSuccess && !$hasAssertion) {
                throw new \Exception(
                    "Invalid Response. A successful Response must contain exactly one Assertion"
                );
            }
        }

        $signatures = $this->xml->getElementsByTagNameNS($ns_signature, 'Signature');
        if ($hasAssertion && $signatures->length == 0) {
            throw new \Exception("Invalid Response. Response must contain at least one signature");
        }

        $responseSignature = null;
        $assertionSignature = null;
        if ($signatures->length > 0) {
            foreach ($signatures as $key => $item) {
                $parent = $item->parentNode;
                // Only a signature directly protecting the assertion or the
                // protocol root is meaningful; one placed anywhere else, or a
                // second signature on the same element, is a wrapping attempt.
                if ($parent->localName == 'Assertion' && $parent->namespaceURI == $ns_saml) {
                    if (!is_null($assertionSignature)) {
                        throw new \Exception("Invalid Response. The Assertion must not carry more than one signature");
                    }
                    $assertionSignature = $item;
                } elseif ($parent->localName == $this->root && $parent->namespaceURI == $ns_samlp) {
                    if (!is_null($responseSignature)) {
                        throw new \Exception("Invalid Response. The Response must not carry more than one signature");
                    }
                    $responseSignature = $item;
                } else {
                    throw new \Exception("Invalid Response. Signature found in an unexpected position");
                }
            }
            if ($hasAssertion && is_null($assertionSignature)) {
                throw new \Exception("Invalid Response. Assertion must be signed");
            }
        }
        if (in_array($this->root, ['LogoutResponse', 'LogoutRequest'], true) && is_null($responseSignature)) {
            throw new \Exception("Invalid $this->root. Message must be signed");
        }

        if (!is_null($responseSignature) && !SignatureUtils::validateXmlSignature($responseSignature, $cert)) {
            throw new \Exception("Invalid Response. Signature validation failed");
        }
        if (!is_null($assertionSignature) && !SignatureUtils::validateXmlSignature($assertionSignature, $cert)) {
            throw new \Exception("Invalid Response. Signature validation failed");
        }

        // Defence in depth against signature wrapping: every identity-bearing
        // element that the downstream validation and the attribute extraction
        // read with getElementsByTagName(...)->item(0) MUST live inside the
        // assertion that was just cryptographically validated. If any such
        // element also appears outside it, item(0) could return the forged copy
        // instead of the signed one, so the response is rejected.
        if ($hasAssertion) {
            $this->assertNoElementsOutsideAssertion($assertionSignature->parentNode);
        }

        return $this->response->validate($this->xml, $hasAssertion);
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