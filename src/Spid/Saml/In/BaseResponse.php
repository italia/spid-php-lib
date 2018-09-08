<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Saml\SignatureUtils;

class BaseResponse
{
    var $response;
    var $xml;

    public function __construct()
    {
        if (!isset($_POST) || !isset($_POST['SAMLResponse'])) {
            return;
        }
        $xmlString = base64_decode($_POST['SAMLResponse']);
        $this->xml = new \DOMDocument();
        $this->xml->loadXML($xmlString);

        $root = $this->xml->documentElement->tagName;

        switch ($root) {
            case 'samlp:Response':
                $this->response = new Response();
                break;
            case 'samlp:LogoutResponse':
                $this->response = new LogoutResponse();
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
        $signatures = $this->xml->getElementsByTagName('Signature');
        if ($signatures->length == 0) throw new \Exception("Invalid Response. Response must contain at least one signature");

        $hasAssertion = $this->xml->getElementsByTagName('Assertion')->length > 0;
        $responseSignature = null;
        $assertionSignature = null;
        foreach ($signatures as $key => $item) {
            if ($item->parentNode->nodeName == 'saml:Assertion') $assertionSignature = $item;
            if ($item->parentNode->nodeName == $this->xml->firstChild->nodeName) $responseSignature = $item;
        }
        if ($hasAssertion && is_null($assertionSignature)) throw new \Exception("Invalid Response. Assertion must be signed");
        
        if (!SignatureUtils::validateXmlSignature($responseSignature, $cert) || !SignatureUtils::validateXmlSignature($assertionSignature, $cert))
            throw new \Exception("Invalid Response. Signature validation failed");
        return $this->response->validate($this->xml);
    }
}
