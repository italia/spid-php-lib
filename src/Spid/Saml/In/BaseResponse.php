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
        $cert = $this->idp;
        if (!SignatureUtils::validateXmlSignature($responseSignature, $cert) || !SignatureUtils::validateXmlSignature($assertionSignature, $cert))
            throw new \Exception("Invalid Response. Signature validation failed");
        return $this->response->validate($this->xml);
/*
            $cert = $idpData['x509cert'];
            $fingerprint = $idpData['certFingerprint'];
            $fingerprintalg = $idpData['certFingerprintAlgorithm'];

            $multiCerts = null;
            $existsMultiX509Sign = isset($idpData['x509certMulti']) && isset($idpData['x509certMulti']['signing']) && !empty($idpData['x509certMulti']['signing']);

            if ($existsMultiX509Sign) {
                $multiCerts = $idpData['x509certMulti']['signing'];
            }

            // If find a Signature on the Response, validates it checking the original response
            if ($hasSignedResponse && !Utils::validateSign($this->document, $cert, $fingerprint, $fingerprintalg, Utils::RESPONSE_SIGNATURE_XPATH, $multiCerts)) {
                throw new ValidationError(
                    "Signature validation failed. SAML Response rejected",
                    ValidationError::INVALID_SIGNATURE
                );
            }

            // If find a Signature on the Assertion (decrypted assertion if was encrypted)
            $documentToCheckAssertion = $this->encrypted ? $this->decryptedDocument : $this->document;
            if ($hasSignedAssertion && !Utils::validateSign($documentToCheckAssertion, $cert, $fingerprint, $fingerprintalg, Utils::ASSERTION_SIGNATURE_XPATH, $multiCerts)) {
                throw new ValidationError(
                    "Signature validation failed. SAML Response rejected",
                    ValidationError::INVALID_SIGNATURE
                );
            }
        }*/
        /*return $this->response->validate($this->xml);*/
    }
}
