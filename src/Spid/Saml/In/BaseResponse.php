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

    public function __construct(Saml $saml = null)
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
        $hasAssertion = $this->xml->getElementsByTagNameNS($ns_saml, 'Assertion')->length > 0;

        $ns_signature = 'http://www.w3.org/2000/09/xmldsig#';
        $signatures = $this->xml->getElementsByTagNameNS($ns_signature, 'Signature');
        if ($hasAssertion && $signatures->length == 0) {
            throw new \Exception("Invalid Response. Response must contain at least one signature");
        }

        $responseSignature = null;
        $assertionSignature = null;
        if ($signatures->length > 0) {
            foreach ($signatures as $key => $item) {
                if ($item->parentNode->localName == 'Assertion') {
                    $assertionSignature = $item;
                }
                if ($item->parentNode->localName == $this->root) {
                    $responseSignature = $item;
                }
            }
            if ($hasAssertion && is_null($assertionSignature)) {
                throw new \Exception("Invalid Response. Assertion must be signed");
            }
        }
        if (!SignatureUtils::validateXmlSignature($responseSignature, $cert) ||
            !SignatureUtils::validateXmlSignature($assertionSignature, $cert)) {
            throw new \Exception("Invalid Response. Signature validation failed");
        }
        return $this->response->validate($this->xml, $hasAssertion);
    }

    public function getXml()
    {
        if ($this->xml) {
            return $this->xml->getElementsByTagName('Response')->item(0);
        } else {
            return '';
        }
    }
}
