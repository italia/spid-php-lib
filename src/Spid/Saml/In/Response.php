<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Interfaces\ResponseInterface;
use Italia\Spid\Spid\Session;
use Italia\Spid\Spid\Saml;
use Italia\Spid\Spid\Exceptions\SpidException;

class Response implements ResponseInterface
{

    private $saml;

    public function __construct(Saml $saml)
    {
        $this->saml = $saml;
    }

    /**
     * @param $xml
     * @param $hasAssertion
     * @return bool
     * @throws SpidException
     */
    public function validate($xml, $hasAssertion): bool
    {
        $accepted_clock_skew_seconds = $this->saml->settings['accepted_clock_skew_seconds'] ?? 0;
        $xmlString = $xml->saveXML();

        $root = $xml->getElementsByTagName('Response')->item(0);

        if ($root->getAttribute('Version') == "") {
            throw new SpidException("Missing Version attribute", $xmlString);
        } elseif ($root->getAttribute('Version') != '2.0') {
            throw new SpidException("Invalid Version attribute", $xmlString);
        }
        if ($root->getAttribute('IssueInstant') == "") {
            throw new SpidException("Missing IssueInstant attribute on Response", $xmlString);
        } elseif (!$this->validateDate($root->getAttribute('IssueInstant'))) {
            throw new SpidException("Invalid IssueInstant attribute on Response", $xmlString);
        } elseif (strtotime($root->getAttribute('IssueInstant')) > strtotime('now') + $accepted_clock_skew_seconds) {
            throw new SpidException("IssueInstant attribute on Response is in the future", $xmlString);
        }

        if ($root->getAttribute('InResponseTo') == "" || !isset($_SESSION['RequestID'])) {
            throw new SpidException("Missing InResponseTo attribute, or request ID was not saved correctly " .
                "for comparison", $xmlString);
        } elseif ($root->getAttribute('InResponseTo') != $_SESSION['RequestID']) {
            throw new SpidException("Invalid InResponseTo attribute, expected " . $_SESSION['RequestID'] .
                " but received " . $root->getAttribute('InResponseTo'), $xmlString);
        }

        if ($root->getAttribute('Destination') == "") {
            throw new SpidException("Missing Destination attribute", $xmlString);
        } elseif ($root->getAttribute('Destination') != $_SESSION['acsUrl']) {
            throw new SpidException("Invalid Destination attribute, expected " . $_SESSION['acsUrl'] .
                " but received " . $root->getAttribute('Destination'), $xmlString);
        }

        if ($xml->getElementsByTagName('Issuer')->length == 0) {
            throw new SpidException("Missing Issuer attribute", $xmlString);
            //check item 0, this the Issuer element child of Response
        } elseif ($xml->getElementsByTagName('Issuer')->item(0)->nodeValue != $_SESSION['idpEntityId']) {
            throw new SpidException("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] .
                " but received " . $xml->getElementsByTagName('Issuer')->item(0)->nodeValue, $xmlString);
        } elseif ($xml->getElementsByTagName('Issuer')->item(0)->getAttribute('Format') !=
            'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
            throw new SpidException("Invalid Issuer attribute, expected 'urn:oasis:names:tc:SAML:2.0" .
                ":nameid-format:entity' but received " . $xml->getElementsByTagName('Issuer')->item(0)
                    ->getAttribute('Format'), $xmlString);
        }

        if ($hasAssertion) {
            if ($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('ID') == "" ||
                $xml->getElementsByTagName('Assertion')->item(0)->getAttribute('ID') == null) {
                throw new SpidException("Missing ID attribute on Assertion", $xmlString);
            } elseif ($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('Version') != '2.0') {
                throw new SpidException("Invalid Version attribute on Assertion", $xmlString);
            } elseif ($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('IssueInstant') == "") {
                throw new SpidException("Invalid IssueInstant attribute on Assertion", $xmlString);
            } elseif (!$this->validateDate(
                $xml->getElementsByTagName('Assertion')->item(0)->getAttribute('IssueInstant')
            )) {
                throw new SpidException("Invalid IssueInstant attribute on Assertion", $xmlString);
            } elseif (strtotime($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('IssueInstant')) >
                strtotime('now') + $accepted_clock_skew_seconds) {
                throw new SpidException("IssueInstant attribute on Assertion is in the future", $xmlString);
            }

            // check item 1, this must be the Issuer element child of Assertion
            if ($hasAssertion && $xml->getElementsByTagName('Issuer')->item(1)->nodeValue != $_SESSION['idpEntityId']) {
                throw new SpidException("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] .
                    " but received " . $xml->getElementsByTagName('Issuer')->item(1)->nodeValue, $xmlString);
            } elseif ($xml->getElementsByTagName('Issuer')->item(1)->getAttribute('Format') !=
                'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
                throw new SpidException("Invalid Issuer attribute, expected 'urn:oasis:names:tc:SAML:2.0:" .
                    "nameid-format:entity' but received " . $xml->getElementsByTagName('Issuer')->item(1)
                        ->getAttribute('Format'), $xmlString);
            }

            if ($xml->getElementsByTagName('Conditions')->length == 0) {
                throw new SpidException("Missing Conditions attribute", $xmlString);
            } elseif ($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore') == "") {
                throw new SpidException("Missing NotBefore attribute", $xmlString);
            } elseif (!$this->validateDate(
                $xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore')
            )) {
                throw new SpidException("Invalid NotBefore attribute", $xmlString);
            } elseif (strtotime($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotBefore')) >
                strtotime('now') + $accepted_clock_skew_seconds) {
                throw new SpidException("NotBefore attribute is in the future", $xmlString);
            } elseif ($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter') == "") {
                throw new SpidException("Missing NotOnOrAfter attribute", $xmlString);
            } elseif (!$this->validateDate(
                $xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter')
            )) {
                throw new SpidException("Invalid NotOnOrAfter attribute", $xmlString);
            } elseif (strtotime($xml->getElementsByTagName('Conditions')->item(0)->getAttribute('NotOnOrAfter')) <=
                strtotime('now') - $accepted_clock_skew_seconds) {
                throw new SpidException("NotOnOrAfter attribute is in the past", $xmlString);
            }

            if ($xml->getElementsByTagName('AudienceRestriction')->length == 0) {
                throw new SpidException("Missing AudienceRestriction attribute", $xmlString);
            }

            if ($xml->getElementsByTagName('Audience')->length == 0) {
                throw new SpidException("Missing Audience attribute", $xmlString);
            } elseif ($xml->getElementsByTagName('Audience')->item(0)->nodeValue !=
                $this->saml->settings['sp_entityid']) {
                throw new SpidException("Invalid Audience attribute, expected " . $this->saml->settings['sp_entityid'] .
                    " but received " . $xml->getElementsByTagName('Audience')->item(0)->nodeValue, $xmlString);
            }

            if ($xml->getElementsByTagName('NameID')->length == 0) {
                throw new SpidException("Missing NameID attribute");
            } elseif ($xml->getElementsByTagName('NameID')->item(0)->getAttribute('Format') !=
                'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
                throw new SpidException("Invalid NameID attribute, expected " .
                "'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'" . " but received " .
                $xml->getElementsByTagName('NameID')->item(0)->getAttribute('Format'), $xmlString);
            } elseif ($xml->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier') !=
                $_SESSION['idpEntityId']) {
                throw new SpidException("Invalid NameQualifier attribute, expected " . $_SESSION['idpEntityId'] .
                    " but received " . $xml->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier'),
                    $xmlString);
            }

            if ($xml->getElementsByTagName('SubjectConfirmationData')->length == 0) {
                throw new SpidException("Missing SubjectConfirmationData attribute", $xmlString);
            } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('InResponseTo') !=
                $_SESSION['RequestID']) {
                throw new SpidException("Invalid SubjectConfirmationData attribute, expected " . $_SESSION['RequestID'] .
                    " but received " . $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('InResponseTo'),
                    $xmlString);
            } elseif (strtotime(
                $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('NotOnOrAfter')
            ) <= strtotime('now') - $accepted_clock_skew_seconds) {
                throw new SpidException("Invalid NotOnOrAfter attribute", $xmlString);
            } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient') !=
                $_SESSION['acsUrl']) {
                throw new SpidException("Invalid Recipient attribute, expected " . $_SESSION['acsUrl'] .
                    " but received " . $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient'),
                    $xmlString);
            } elseif ($xml->getElementsByTagName('SubjectConfirmation')->item(0)->getAttribute('Method') !=
                'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
                throw new SpidException("Invalid Method attribute, expected 'urn:oasis:names:tc:SAML:2.0:cm:bearer'" .
                    " but received " .
                    $xml->getElementsByTagName('SubjectConfirmation')->item(0)->getAttribute('Method'), $xmlString);
            }

            if ($xml->getElementsByTagName('Attribute')->length == 0) {
                throw new SpidException("Missing Attribute Element", $xmlString);
            }

            if ($xml->getElementsByTagName('AttributeValue')->length == 0) {
                throw new SpidException("Missing AttributeValue Element", $xmlString);
            }
        }

        if ($xml->getElementsByTagName('Status')->length <= 0) {
            throw new SpidException("Missing Status element", $xmlString);
        } elseif ($xml->getElementsByTagName('Status')->item(0) == null) {
            throw new SpidException("Missing Status element", $xmlString);
        } elseif ($xml->getElementsByTagName('StatusCode')->item(0) == null) {
            throw new SpidException("Missing StatusCode element", $xmlString);
        } elseif ($xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') ==
            'urn:oasis:names:tc:SAML:2.0:status:Success') {
            if ($hasAssertion && $xml->getElementsByTagName('AuthnStatement')->length <= 0) {
                throw new SpidException("Missing AuthnStatement element", $xmlString);
            }
        } elseif ($xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') !=
            'urn:oasis:names:tc:SAML:2.0:status:Success') {
            if ($xml->getElementsByTagName('StatusMessage')->item(0) != null) {
                $StatusMessage = ' [message: ' . $xml->getElementsByTagName('StatusMessage')->item(0)->nodeValue . ']';
            } else {
                $StatusMessage = "";
            }
            throw new SpidException("StatusCode is not Success" . $StatusMessage, $xmlString);
        } elseif ($xml->getElementsByTagName('StatusCode')->item(1)->getAttribute('Value') ==
            'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed') {
            throw new SpidException("AuthnFailed AuthnStatement element", $xmlString);
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
