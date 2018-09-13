<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Interfaces\ResponseInterface;

class LogoutRequest implements ResponseInterface
{
    public function validate($xml) : bool
    {
        $root = $xml->getElementsByTagName('LogoutRrquest')->item(0);

        if ($xml->getElementsByTagName('Issuer')->length == 0) throw new \Exception("Invalid Response. Missing Issuer element");
        if ($xml->getElementsByTagName('NameID')->length == 0) throw new \Exception("Invalid Response. Missing NameID element");
        if ($xml->getElementsByTagName('SessionIndex')->length == 0) throw new \Exception("Invalid Response. Missing SessionIndex element");
        
        $issuer = $xml->getElementsByTagName('Issuer')->item(0);
        if ($issuer->getAttribute('Format') == "") {
            throw new \Exception("Missing Format attribute");
        } elseif ($issuer->getAttribute('Format') != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") {
            throw new \Exception("Invalid Format attribute");
        }
        if ($issuer->getAttribute('NameQualifier') == "") {
            throw new \Exception("Missing NameQualifier attribute");
        } elseif ($issuer->getAttribute('NameQualifier') != $_SESSION['spidSession']->idpEntityID) {
            throw new \Exception("Invalid NameQualifier attribute");
        }

        //geerate logoutResponse??
    }
}