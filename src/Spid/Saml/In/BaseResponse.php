<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Saml\SignatureUtils;
use Italia\Spid\Spid\Saml;
use Italia\Spid\Spid\Exceptions\SpidException;

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
    private $xmlString;

    /**
     * @param Saml|null $saml
     * @throws SpidException
     */
    public function __construct(Saml $saml = null)
    {
        if ((!isset($_POST) || !isset($_POST['SAMLResponse'])) &&
            (!isset($_GET) || !isset($_GET['SAMLResponse']))
        ) {
            return;
        }

        $this->xmlString = isset($_GET['SAMLResponse']) ?
            gzinflate(base64_decode($_GET['SAMLResponse'])) :
            base64_decode($_POST['SAMLResponse']);

        $this->xml = new \DOMDocument();
        $this->xml->loadXML($this->xmlString);

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
                $data = [
                    "RequestID" => $_SESSION['RequestID'],
                    "idpName" => $_SESSION['idpName'],
                    "idpEntityId" => $_SESSION['idpEntityId'],
                    "acsUrl" => $_SESSION['acsUrl'],
                    "XML" => $this->xmlString
                ];
                throw new SpidException('No valid response found', json_encode($data));
        }
    }

    /**
     * @param $cert
     * @return bool
     * @throws SpidException
     * @throws Exception
     */
    public function validate($cert): bool
    {
        if (is_null($this->response)) {
            return true;
        }

        $ns_saml = 'urn:oasis:names:tc:SAML:2.0:assertion';
        $hasAssertion = $this->xml->getElementsByTagNameNS($ns_saml, 'Assertion')->length > 0;

        $ns_signature = 'http://www.w3.org/2000/09/xmldsig#';
        $signatures = $this->xml->getElementsByTagNameNS($ns_signature, 'Signature');
        if ($hasAssertion && $signatures->length == 0) {
            throw new SpidException('Invalid Response. Response must contain at least one signature', $this->xmlString);
        }

        $responseSignature = null;
        $assertionSignature = null;
        if ($signatures->length > 0) {
            foreach ($signatures as $item) {
                /** @var \DOMNode $item */
                if ($item->parentNode->localName == 'Assertion') {
                    $assertionSignature = $item;
                }
                if ($item->parentNode->localName == $this->root) {
                    $responseSignature = $item;
                }
            }

            if ($hasAssertion && is_null($assertionSignature)) {
                throw new SpidException('Invalid Response. Assertion must be signed', $this->xmlString);
            }
        }

        if (is_null($responseSignature)) {
            throw new SpidException(
                'Invalid Response. responseSignature is empty',
                $this->xmlString,
                $this->getErrorCodeFromXml()
            );
        }

        if (is_null($assertionSignature)) {
            throw new SpidException(
                'Invalid Response. assertionSignature is empty',
                $this->xmlString,
                $this->getErrorCodeFromXml()
            );
        }

        if (!SignatureUtils::validateXmlSignature($responseSignature, $cert)) {
            throw new SpidException(
                'Invalid Response. responseSignature validation failed',
                $this->xmlString,
                $this->getErrorCodeFromXml()
            );
        }

        if (!SignatureUtils::validateXmlSignature($assertionSignature, $cert)) {
            throw new SpidException(
                'Invalid Response. assertionSignature validation failed',
                $this->xmlString,
                $this->getErrorCodeFromXml()
            );
        }

        try {
            return $this->response->validate($this->xml, $hasAssertion);
        } catch (\Exception $e) {
            throw new SpidException(
                'Invalid Response. response validation failed with exception: ' . $e->getMessage(),
                $this->xmlString,
                $this->getErrorCodeFromXml(),
                $e
            );
        }
    }

    /**
     * @return int
     */
    private function getErrorCodeFromXml(): int
    {
        $statusMessage = $this->xml->getElementsByTagName('StatusMessage');
        if ($statusMessage && $statusMessage->item(0) && $statusMessage->item(0)->nodeValue) {
            $errorString = $statusMessage->item(0)->nodeValue;
            $errorCode = filter_var(str_replace('ErrorCode nr', '', $errorString), FILTER_VALIDATE_INT);
            return $errorCode === false ? -1 : $errorCode;
        }
        return -1;
    }
}
