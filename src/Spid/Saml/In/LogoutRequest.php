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

    public function validate($xml, $assertion) : bool
    {
        $root = $xml->documentElement;

        if (!isset($_SESSION['spidSession']) || !is_array($_SESSION['spidSession'])) {
            throw new \Exception("Invalid Response. No authenticated session to terminate");
        }
        $spidSession = $_SESSION['spidSession'];

        if ($xml->getElementsByTagName('Issuer')->length == 0) {
            throw new \Exception("Invalid Response. Missing Issuer element");
        }
        if ($xml->getElementsByTagName('NameID')->length == 0) {
            throw new \Exception("Invalid Response. Missing NameID element");
        }
        if ($xml->getElementsByTagName('SessionIndex')->length == 0) {
            throw new \Exception("Invalid Response. Missing SessionIndex element");
        }

        $issuer = $xml->getElementsByTagName('Issuer')->item(0);
        $nameId = $xml->getElementsByTagName('NameID')->item(0);
        $sessionIndex = $xml->getElementsByTagName('SessionIndex')->item(0);

        // Destination belongs to the LogoutRequest root, not to its Issuer: reading
        // it off the Issuer element meant the attribute was never actually checked.
        if ($root->getAttribute('Destination') == "") {
            throw new \Exception("Missing Destination attribute");
        } elseif ($root->getAttribute('Destination') != $this->saml->settings['sp_entityid']) {
            throw new \Exception("Invalid Destination attribute, expected " .
                $this->saml->settings['sp_entityid'] . " but received " . $root->getAttribute('Destination'));
        }

        if ($issuer->getAttribute('Format') == "") {
            throw new \Exception("Missing Format attribute");
        } elseif ($issuer->getAttribute('Format') != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") {
            throw new \Exception("Invalid Format attribute");
        }
        if ($issuer->nodeValue != $spidSession['idpEntityID']) {
            throw new \Exception("Invalid Issuer, expected " . $spidSession['idpEntityID'] .
                " but received " . $issuer->nodeValue);
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
