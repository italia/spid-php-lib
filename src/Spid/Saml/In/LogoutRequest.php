<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Interfaces\ResponseInterface;
use Italia\Spid\Spid\Saml;

class LogoutRequest implements ResponseInterface
{

    private $saml;

    public function __construct(Saml $saml)
    {
        $this->saml = $saml;
    }

    public function validate($xml, $hasAssertion) : bool
    {
        $root = $xml->getElementsByTagName('LogoutRequest')->item(0);

        if ($xml->getElementsByTagName('Issuer')->length == 0) {
            throw new \Exception("Invalid Response. Missing Issuer element");
        }
        if ($xml->getElementsByTagName('NameID')->length == 0) {
            throw new \Exception("Invalid Response. Missing NameID element");
        }
        if ($xml->getElementsByTagName('SessionIndex')->length == 0) {
            throw new \Exception("Invalid Response. Missing SessionIndex element");
        }
        if ($root->getAttribute('Destination') == "") {
            throw new \Exception("Missing Destination attribute");
        } elseif ($root->getAttribute('Destination') != $this->saml->settings['sp_entityid']) {
            throw new \Exception("Invalid Destination attribute");
        }

        $issuer = $xml->getElementsByTagName('Issuer')->item(0);
        $nameId = $xml->getElementsByTagName('NameID')->item(0);
        $sessionIndex = $xml->getElementsByTagName('SessionIndex')->item(0);
        $spidSession = $_SESSION['spidSession'] ?? null;
        if (!is_array($spidSession)) {
            throw new \Exception("No active SPID session to log out");
        }

        if ($issuer->getAttribute('Format') == "") {
            throw new \Exception("Missing Format attribute");
        } elseif ($issuer->getAttribute('Format') != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") {
            throw new \Exception("Invalid Format attribute");
        }
        if ($issuer->getAttribute('NameQualifier') == "") {
            throw new \Exception("Missing NameQualifier attribute");
        } elseif ($issuer->getAttribute('NameQualifier') != $spidSession['idpEntityID']) {
            throw new \Exception("Invalid NameQualifier attribute");
        }

        if ($nameId->getAttribute('Format') == "") {
            throw new \Exception("Missing NameID Format attribute");
        } elseif ($nameId->getAttribute('Format') != "urn:oasis:names:tc:SAML:2.0:nameid-format:transient") {
            throw new \Exception("Invalid NameID Format attribute");
        }
        if ($nameId->getAttribute('NameQualifier') == "") {
            throw new \Exception("Missing NameID NameQualifier attribute");
        } elseif ($nameId->getAttribute('NameQualifier') != $spidSession['idpEntityID']) {
            throw new \Exception("Invalid NameID NameQualifier attribute");
        }

        if ($sessionIndex->nodeValue != $spidSession['sessionID']) {
            throw new \Exception("Invalid SessionID, expected " . $spidSession['sessionID'] .
                " but received " . $sessionIndex->nodeValue);
        }
        $_SESSION['inResponseTo'] = $root->getAttribute('ID');
        return true;
    }
}
