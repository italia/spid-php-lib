<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Interfaces\ResponseInterface;
use Italia\Spid\Spid\Session;
use Italia\Spid\Spid\Saml;

class Response implements ResponseInterface
{

    private $saml;

    public function __construct(Saml $saml)
    {
        $this->saml = $saml;
    }

    public function validate($xml, $hasAssertion): bool
    {
        $root = $xml->getElementsByTagName('Response')->item(0);

        if ($root->getAttribute('Version') == "") {
            throw new \Exception("Missing Version attribute");
        } elseif ($root->getAttribute('Version') != '2.0') {
            throw new \Exception("Invalid Version attribute");
        }
        if ($root->getAttribute('IssueInstant') == "") {
            throw new \Exception("Missing IssueInstant attribute");
        }
        if ($root->getAttribute('InResponseTo') == "" || !isset($_SESSION['RequestID'])) {
            throw new \Exception("Missing InResponseTo attribute, or request ID was not saved correctly for comparison");
        } elseif ($root->getAttribute('InResponseTo') != $_SESSION['RequestID']) {
            throw new \Exception("Invalid InResponseTo attribute, expected " . $_SESSION['RequestID'] . " but received " . $root->getAttribute('InResponseTo'));
        }
        if ($root->getAttribute('Destination') == "") {
            throw new \Exception("Missing Destination attribute");
        } elseif ($root->getAttribute('Destination') != $_SESSION['acsUrl']) {
            throw new \Exception("Invalid Destination attribute, expected " . $_SESSION['acsUrl'] . " but received " . $root->getAttribute('Destination'));
        }
        if ($xml->getElementsByTagName('Issuer')->length == 0) {
            throw new \Exception("Missing Issuer attribute");
            //check item 0, this the Issuer element child of Response
        } elseif ($xml->getElementsByTagName('Issuer')->item(0)->nodeValue != $_SESSION['idpEntityId']) {
            throw new \Exception("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] . " but received " . $xml->getElementsByTagName('Issuer')->item(0)->nodeValue);
        }
        if ($hasAssertion) {
            //check item 1, this the Issuer element child of Assertion
            if ($hasAssertion && $xml->getElementsByTagName('Issuer')->item(1)->nodeValue != $_SESSION['idpEntityId']) {
                throw new \Exception("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] . " but received " . $xml->getElementsByTagName('Issuer')->item(1)->nodeValue);
            }
            if ($xml->getElementsByTagName('Conditions')->length == 0) {
                throw new \Exception("Missing Conditions attribute");
            } elseif ($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore') == "" || strtotime($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore')) > strtotime('now')) {
                throw new \Exception("Invalid NotBefore attribute");
            } elseif ($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter') == "" || strtotime($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter')) < strtotime('now')) {
                throw new \Exception("Invalid NotOnOrAfter attribute");
            }
            if ($xml->getElementsByTagName('AudienceRestriction')->length == 0) {
                throw new \Exception("Missing AudienceRestriction attribute");
            }
            if ($xml->getElementsByTagName('Audience')->length == 0) {
                throw new \Exception("Missing Audience attribute");
            } elseif ($xml->getElementsByTagName('Audience')->item(0)->nodeValue != $this->saml->settings['sp_entityid']) {
                throw new \Exception("Invalid Audience attribute, expected " . $this->saml->settings['sp_entityid'] . " but received " . $xml->getElementsByTagName('Audience')->item(0)->nodeValue);
            }
            if ($xml->getElementsByTagName('NameID')->length == 0) {
                throw new \Exception("Missing NameID attribute");
            } elseif ($xml->getElementsByTagName('NameID')->item(0)->getAttribute('Format') != 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
                throw new \Exception("Invalid NameID attribute, expected 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'" . " but received " . $xml->getElementsByTagName('NameID')->item(0)->getAttribute('Format'));
            } elseif ($xml->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier') != $_SESSION['idpEntityId']) {
                throw new \Exception("Invalid NameQualifier attribute, expected " . $_SESSION['idpEntityId'] . " but received " . $xml->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier'));
            }
            if ($xml->getElementsByTagName('SubjectConfirmationData')->length == 0) {
                throw new \Exception("Missing SubjectConfirmationData attribute");
            } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('InResponseTo') != $_SESSION['RequestID']) {
                throw new \Exception("Invalid SubjectConfirmationData attribute, expected " . $_SESSION['RequestID'] . " but received " . $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('InResponseTo'));
            } elseif (strtotime($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('NotOnOrAfter')) < strtotime('now')) {
                throw new \Exception("Invalid NotOnOrAfter attribute");
            } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient') != $_SESSION['acsUrl']) {
                throw new \Exception("Invalid Recipient attribute, expected " . $_SESSION['acsUrl'] . " but received " . $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient'));
            }
        }
    
        if ($xml->getElementsByTagName('Status')->length <= 0) {
            throw new \Exception("Missing Status element");
        } elseif ($xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') == 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            if ($hasAssertion && $xml->getElementsByTagName('AuthnStatement')->length <= 0) {
                throw new \Exception("Missing AuthnStatement element");
            }
        } else {
            // Status code != success
            return false;
        }

        // Response OK
        $session = $this->spidSession($xml);
        $_SESSION['spidSession'] = (array)$session;
        unset($_SESSION['RequestID']);
        unset($_SESSION['idpName']);
        unset($_SESSION['idpEntityId']);
        unset($_SESSION['acsUrl']);
        return true;
    }

    private function spidSession(\DOMDocument $xml)
    {
        $session = new Session();

        $attributes = array();
        if ($xml->getElementsByTagName('AttributeStatement')->length > 0) {
            foreach ($xml->getElementsByTagName('AttributeStatement')->item(0)->childNodes as $attr) {
                $attributes[$attr->getAttribute('Name')] = $attr->nodeValue;
            }
        }

        $session->sessionID = $_SESSION['RequestID'];
        $session->idp = $_SESSION['idpName'];
        $session->idpEntityID = $xml->getElementsByTagName('Issuer')->item(0)->nodeValue;
        $session->attributes = $attributes;
        $session->level = substr($xml->getElementsByTagName('AuthnContextClassRef')->item(0)->nodeValue, -1);
        return $session;
    }
}
