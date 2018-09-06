<?php

namespace Italia\Spid\Spid\Saml\In;

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

    public function validate() : bool
    {
        if (is_null($this->response)) {
            return true;
        }
        $this->xml->getElementsByTagName('Signature');
        if (empty($signedElements) || (!$hasSignedResponse && !$hasSignedAssertion)) {
            throw new ValidationError(
                'No Signature found. SAML Response rejected',
                ValidationError::NO_SIGNATURE_FOUND
            );
        } else {
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
        }
        return $this->response->validate($this->xml);
    }
}
