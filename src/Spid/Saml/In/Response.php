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
        $accepted_clock_skew_seconds = isset($this->saml->settings['accepted_clock_skew_seconds']) ?
            $this->saml->settings['accepted_clock_skew_seconds'] : 0;

        $root = $xml->getElementsByTagName('Response')->item(0);

        if ($root->getAttribute('Version') == "") {
            throw new \Exception("Missing Version attribute");
        } elseif ($root->getAttribute('Version') != '2.0') {
            throw new \Exception("Invalid Version attribute");
        }
        if ($root->getAttribute('IssueInstant') == "") {
            throw new \Exception("Missing IssueInstant attribute on Response");
        } elseif (!$this->validateDate($root->getAttribute('IssueInstant'))) {
            throw new \Exception("Invalid IssueInstant attribute on Response");
        } elseif (strtotime($root->getAttribute('IssueInstant')) > strtotime('now') + $accepted_clock_skew_seconds) {
            throw new \Exception("IssueInstant attribute on Response is in the future");
        }

        if ($root->getAttribute('InResponseTo') == "" || !isset($_SESSION['RequestID'])) {
            throw new \Exception("Missing InResponseTo attribute, or request ID was not saved correctly " .
                "for comparison");
        } elseif ($root->getAttribute('InResponseTo') != $_SESSION['RequestID']) {
            throw new \Exception("Invalid InResponseTo attribute, expected " . $_SESSION['RequestID'] .
                " but received " . $root->getAttribute('InResponseTo'));
        }

        if ($root->getAttribute('Destination') == "") {
            throw new \Exception("Missing Destination attribute");
        } elseif ($root->getAttribute('Destination') != $_SESSION['acsUrl']) {
            throw new \Exception("Invalid Destination attribute, expected " . $_SESSION['acsUrl'] .
                " but received " . $root->getAttribute('Destination'));
        }

        if ($xml->getElementsByTagName('Issuer')->length == 0) {
            throw new \Exception("Missing Issuer attribute");
            //check item 0, this the Issuer element child of Response
        } elseif ($xml->getElementsByTagName('Issuer')->item(0)->nodeValue != $_SESSION['idpEntityId']) {
            throw new \Exception("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] .
                " but received " . $xml->getElementsByTagName('Issuer')->item(0)->nodeValue);
        } elseif ($xml->getElementsByTagName('Issuer')->item(0)->getAttribute('Format') !=
            'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
            throw new \Exception("Invalid Issuer attribute, expected 'urn:oasis:names:tc:SAML:2.0:nameid-format:" .
                "entity'" . " but received " . $xml->getElementsByTagName('Issuer')->item(0)->getAttribute('Format'));
        }

        if ($hasAssertion) {
            if ($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('ID') == "" ||
                $xml->getElementsByTagName('Assertion')->item(0)->getAttribute('ID') == null) {
                throw new \Exception("Missing ID attribute on Assertion");
            } elseif ($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('Version') != '2.0') {
                throw new \Exception("Invalid Version attribute on Assertion");
            } elseif ($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('IssueInstant') == "") {
                throw new \Exception("Invalid IssueInstant attribute on Assertion");
            } elseif (!$this->validateDate(
                $xml->getElementsByTagName('Assertion')->item(0)->getAttribute('IssueInstant')
            )) {
                throw new \Exception("Invalid IssueInstant attribute on Assertion");
            } elseif (strtotime($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('IssueInstant')) >
                strtotime('now') + $accepted_clock_skew_seconds) {
                throw new \Exception("IssueInstant attribute on Assertion is in the future");
            }

            // check item 1, this must be the Issuer element child of Assertion
            if ($hasAssertion && $xml->getElementsByTagName('Issuer')->item(1)->nodeValue != $_SESSION['idpEntityId']) {
                throw new \Exception("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] .
                    " but received " . $xml->getElementsByTagName('Issuer')->item(1)->nodeValue);
            } elseif ($xml->getElementsByTagName('Issuer')->item(1)->getAttribute('Format') !=
                'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
                throw new \Exception("Invalid Issuer attribute, expected 'urn:oasis:names:tc:SAML:2.0:nameid-format:" .
                "entity'" . " but received " . $xml->getElementsByTagName('Issuer')->item(1)->getAttribute('Format'));
            }

            if ($xml->getElementsByTagName('Conditions')->length == 0) {
                throw new \Exception("Missing Conditions attribute");
            } elseif ($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore') == "") {
                throw new \Exception("Missing NotBefore attribute");
            } elseif (!$this->validateDate(
                $xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore')
            )) {
                throw new \Exception("Invalid NotBefore attribute");
            } elseif (strtotime($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore')) >
                strtotime('now') + $accepted_clock_skew_seconds) {
                throw new \Exception("NotBefore attribute is in the future");
            } elseif ($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter') == "") {
                throw new \Exception("Missing NotOnOrAfter attribute");
            } elseif (!$this->validateDate(
                $xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter')
            )) {
                throw new \Exception("Invalid NotOnOrAfter attribute");
            } elseif (strtotime($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter')) <=
                strtotime('now') - $accepted_clock_skew_seconds) {
                throw new \Exception("NotOnOrAfter attribute is in the past");
            }

            if ($xml->getElementsByTagName('AudienceRestriction')->length == 0) {
                throw new \Exception("Missing AudienceRestriction attribute");
            }

            if ($xml->getElementsByTagName('Audience')->length == 0) {
                throw new \Exception("Missing Audience attribute");
            } elseif ($xml->getElementsByTagName('Audience')->item(0)->nodeValue !=
                $this->saml->settings['sp_entityid']) {
                throw new \Exception("Invalid Audience attribute, expected " . $this->saml->settings['sp_entityid'] .
                    " but received " . $xml->getElementsByTagName('Audience')->item(0)->nodeValue);
            }

            if ($xml->getElementsByTagName('NameID')->length == 0) {
                throw new \Exception("Missing NameID attribute");
            } elseif ($xml->getElementsByTagName('NameID')->item(0)->getAttribute('Format') !=
                'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
                throw new \Exception("Invalid NameID attribute, expected " .
                "'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'" . " but received " .
                $xml->getElementsByTagName('NameID')->item(0)->getAttribute('Format'));
            } elseif ($xml->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier') !=
                $_SESSION['idpEntityId']) {
                throw new \Exception("Invalid NameQualifier attribute, expected " . $_SESSION['idpEntityId'] .
                    " but received " . $xml->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier'));
            }

            if ($xml->getElementsByTagName('SubjectConfirmationData')->length == 0) {
                throw new \Exception("Missing SubjectConfirmationData attribute");
            } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('InResponseTo') !=
                $_SESSION['RequestID']) {
                throw new \Exception("Invalid SubjectConfirmationData attribute, expected " . $_SESSION['RequestID'] .
                    " but received " .
                    $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('InResponseTo'));
            } elseif (strtotime(
                $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('NotOnOrAfter')
            ) <= strtotime('now') - $accepted_clock_skew_seconds) {
                throw new \Exception("Invalid NotOnOrAfter attribute");
            } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient') !=
                $_SESSION['acsUrl']) {
                throw new \Exception("Invalid Recipient attribute, expected " . $_SESSION['acsUrl'] .
                    " but received " .
                    $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient'));
            } elseif ($xml->getElementsByTagName('SubjectConfirmation')->item(0)->getAttribute('Method') !=
                'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
                throw new \Exception("Invalid Method attribute, expected 'urn:oasis:names:tc:SAML:2.0:cm:bearer'" .
                    " but received " .
                    $xml->getElementsByTagName('SubjectConfirmation')->item(0)->getAttribute('Method'));
            }

            if ($xml->getElementsByTagName('Attribute')->length == 0) {
                throw new \Exception("Missing Attribute Element");
            }

            if ($xml->getElementsByTagName('AttributeValue')->length == 0) {
                throw new \Exception("Missing AttributeValue Element");
            }
        }

        if ($xml->getElementsByTagName('Status')->length <= 0) {
            throw new \Exception("Missing Status element");
        } elseif ($xml->getElementsByTagName('Status')->item(0) == null) {
            throw new \Exception("Missing Status element");
        } elseif ($xml->getElementsByTagName('StatusCode')->item(0) == null) {
            throw new \Exception("Missing StatusCode element");
        } elseif ($xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') ==
            'urn:oasis:names:tc:SAML:2.0:status:Success') {
            if ($hasAssertion && $xml->getElementsByTagName('AuthnStatement')->length <= 0) {
                throw new \Exception("Missing AuthnStatement element");
            }
        } elseif ($xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') !=
            'urn:oasis:names:tc:SAML:2.0:status:Success') {
            if ($xml->getElementsByTagName('StatusMessage')->item(0) != null) {
                $StatusMessage = ' [message: ' . $xml->getElementsByTagName('StatusMessage')->item(0)->nodeValue . ']';
            } else {
                $StatusMessage = "";
            }
            throw new \Exception("StatusCode is not Success" . $StatusMessage);
        } elseif ($xml->getElementsByTagName('StatusCode')->item(1)->getAttribute('Value') ==
            'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed') {
            throw new \Exception("AuthnFailed AuthnStatement element");
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

    private function validateDate($date)
    {
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/', $date, $parts) == true) {
            $time = gmmktime($parts[4], $parts[5], $parts[6], $parts[2], $parts[3], $parts[1]);

            $input_time = strtotime($date);
            if ($input_time === false) {
                return false;
            }

            return $input_time == $time;
        } else {
            return false;
        }
    }

    private function spidSession(\DOMDocument $xml)
    {
        $session = new Session();

        $attributes = array();
        $attributeStatements = $xml->getElementsByTagName('AttributeStatement');

        if ($attributeStatements->length > 0) {
            foreach ($attributeStatements->item(0)->childNodes as $attr) {
                if ($attr->hasAttributes()) {
                    $attributes[$attr->attributes->getNamedItem('Name')->value] = trim($attr->nodeValue);
                }
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
