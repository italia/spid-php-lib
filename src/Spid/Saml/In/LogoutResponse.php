<?php

namespace Italia\Spid\Spid\Saml\In;

class LogoutResponse extends Base
{
    public function validate()
    {
        if (!isset($_POST) || !isset($_POST['SAMLResponse'])) {
            return false;
        }

        $xmlString = base64_decode($_POST['SAMLResponse']);
        $xml = new \DOMDocument();
        $xml->loadXML($xmlString);

        session_unset();
        return true;
    }
}