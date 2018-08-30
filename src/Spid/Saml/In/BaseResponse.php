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
        return $this->response->validate($this->xml);
    }
}
