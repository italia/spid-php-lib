<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Interfaces\ResponseInterface;

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

        $root = $this->xml->getDocumentElement();
        $root = $root->tagname;

        switch ($root) {
            case 'Response':
                $this->response = new Response();
                break;
            case 'LogoutResponse':
                $this->response = new LogoutResponse();
                break;
            default:
                throw new \Exception('No valid response found');
                break;
        }
    }

    public function validate()
    {
        if (is_null($this->response)) {
            return false;
        }
        return $this->response->validate($this->xml);
    }
}
