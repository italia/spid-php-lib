<?php

namespace Italia\Spid\Spid\Saml\In;

use DOMDocument;
use Italia\Spid\Spid\Exceptions\SpidException;
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

    /**
     * @throws SpidException
     */
    public function validate(DOMDocument $xml, $hasAssertion): bool
    {
        $logger = $this->saml->getLogger();

        $acceptedClockSkewSeconds = $this->saml->settings['accepted_clock_skew_seconds'] ?? 0;
        $minTime = strtotime('now') - $acceptedClockSkewSeconds;
        $maxTime = strtotime('now') + $acceptedClockSkewSeconds;
        $samlUrn = 'urn:oasis:names:tc:SAML:2.0:';

        $root = $xml->getElementsByTagName('Response')->item(0);

        if ($root->getAttribute('Version') == "") {
            $logger->logAndThrow($xml, "Missing Version attribute");
        } elseif ($root->getAttribute('Version') != '2.0') {
            $logger->logAndThrow($xml, "Invalid Version attribute");
        }

        $issueInstant = $root->getAttribute('IssueInstant');
        if ($issueInstant == "") {
            $logger->logAndThrow($xml, "Missing IssueInstant attribute on Response");
        } elseif (!$this->validateDate($issueInstant)) {
            $logger->logAndThrow($xml, "Invalid IssueInstant attribute on Response");
        } elseif (strtotime($issueInstant) > strtotime('now') + $acceptedClockSkewSeconds) {
            $logger->logAndThrow($xml, "IssueInstant attribute on Response is in the future");
        }

        $inResponseTo = $root->getAttribute('InResponseTo');
        if ($inResponseTo == "" || !isset($_SESSION['RequestID'])) {
            $logger->logAndThrow(
                $xml,
                "Missing InResponseTo attribute, or request ID was not saved correctly for comparison"
            );
        } elseif ($inResponseTo != $_SESSION['RequestID']) {
            $logger->logAndThrow(
                $xml,
                "Invalid InResponseTo attribute, expected {$_SESSION['RequestID']} but received " . $inResponseTo
            );
        }

        $destination = $root->getAttribute('Destination');
        if ($destination == "") {
            $logger->logAndThrow($xml, "Missing Destination attribute");
        } elseif ($destination != $_SESSION['acsUrl']) {
            $logger->logAndThrow(
                $xml,
                "Invalid Destination attribute, expected {$_SESSION['acsUrl']} but received " . $destination
            );
        }

        $issuer = $xml->getElementsByTagName('Issuer');
        if ($issuer->length == 0) {
            $logger->logAndThrow($xml, "Missing Issuer attribute");
            //check item 0, this the Issuer element child of Response
        } elseif ($issuer->item(0)->nodeValue != $_SESSION['idpEntityId']) {
            $logger->logAndThrow(
                $xml,
                "Invalid Issuer attribute, expected {$_SESSION['idpEntityId']} but received " .
                $issuer->item(0)->nodeValue
            );
        } elseif (
            $issuer->item(0)->hasAttribute('Format')
            && $issuer->item(0)->getAttribute('Format') != $samlUrn . 'nameid-format:entity'
        ) {
            $logger->logAndThrow(
                $xml,
                "Invalid Issuer attribute, expected '{$samlUrn}nameid-format:entity' but received " .
                $issuer->item(0)->getAttribute('Format')
            );
        }

        if ($hasAssertion) {
            $assertion = $xml->getElementsByTagName('Assertion')->item(0);
            if ($assertion->getAttribute('ID') == "" || $assertion->getAttribute('ID') == null) {
                $logger->logAndThrow($xml, "Missing ID attribute on Assertion");
            } elseif ($assertion->getAttribute('Version') != '2.0') {
                $logger->logAndThrow($xml, "Invalid Version attribute on Assertion");
            } elseif ($assertion->getAttribute('IssueInstant') == "") {
                $logger->logAndThrow($xml, "Invalid IssueInstant attribute on Assertion");
            } elseif (!$this->validateDate($assertion->getAttribute('IssueInstant'))) {
                $logger->logAndThrow($xml, "Invalid IssueInstant attribute on Assertion");
            } elseif (strtotime($assertion->getAttribute('IssueInstant')) > $maxTime) {
                $logger->logAndThrow($xml, "IssueInstant attribute on Assertion is in the future");
            }

            // check item 1, this must be the Issuer element child of Assertion
            if ($issuer->item(1)->nodeValue != $_SESSION['idpEntityId']) {
                $logger->logAndThrow(
                    $xml,
                    "Invalid Issuer attribute, expected {$_SESSION['idpEntityId']} but received " .
                    $issuer->item(1)->nodeValue
                );
            } elseif ($issuer->item(1)->getAttribute('Format') != $samlUrn . 'nameid-format:entity') {
                $logger->logAndThrow(
                    $xml,
                    "Invalid Issuer attribute, expected '{$samlUrn}nameid-format:entity'" .
                     ' but received ' . $issuer->item(1)->getAttribute('Format')
                );
            }

            $conditions = $xml->getElementsByTagName('Conditions');
            if ($conditions->length == 0) {
                $logger->logAndThrow($xml, "Missing Conditions attribute");
            } elseif ($conditions->item(0)->getAttribute('NotBefore') == "") {
                $logger->logAndThrow($xml, "Missing NotBefore attribute");
            } elseif (!$this->validateDate($conditions->item(0)->getAttribute('NotBefore'))) {
                $logger->logAndThrow($xml, "Invalid NotBefore attribute");
            } elseif (strtotime($conditions->item(0)->getAttribute('NotBefore')) > $maxTime) {
                $logger->logAndThrow($xml, "NotBefore attribute is in the future");
            } elseif ($conditions->item(0)->getAttribute('NotOnOrAfter') == "") {
                $logger->logAndThrow($xml, "Missing NotOnOrAfter attribute");
            } elseif (!$this->validateDate($conditions->item(0)->getAttribute('NotOnOrAfter'))) {
                $logger->logAndThrow($xml, "Invalid NotOnOrAfter attribute");
            } elseif (strtotime($conditions->item(0)->getAttribute('NotOnOrAfter')) <= $minTime) {
                $logger->logAndThrow($xml, "NotOnOrAfter attribute is in the past");
            }

            if ($xml->getElementsByTagName('AudienceRestriction')->length == 0) {
                $logger->logAndThrow($xml, "Missing AudienceRestriction attribute");
            }

            $audience = $xml->getElementsByTagName('Audience');
            if ($audience->length == 0) {
                $logger->logAndThrow($xml, "Missing Audience attribute");
            } elseif ($audience->item(0)->nodeValue != $this->saml->settings['sp_entityid']) {
                $logger->logAndThrow(
                    $xml,
                    "Invalid Audience attribute, expected " . $this->saml->settings['sp_entityid'] .
                    " but received " . $audience->item(0)->nodeValue
                );
            }

            $nameId = $xml->getElementsByTagName('NameID');
            if ($nameId->length == 0) {
                $logger->logAndThrow($xml, "Missing NameID attribute");
            } elseif ($nameId->item(0)->getAttribute('Format') != $samlUrn . 'nameid-format:transient') {
                $logger->logAndThrow(
                    $xml,
                    "Invalid NameID attribute, expected '{$samlUrn}nameid-format:transient'" .
                    " but received " . $nameId->item(0)->getAttribute('Format')
                );
            } elseif ($nameId->item(0)->getAttribute('NameQualifier') != $_SESSION['idpEntityId']) {
                $logger->logAndThrow(
                    $xml,
                    "Invalid NameQualifier attribute, expected {$_SESSION['idpEntityId']} but received " .
                    $nameId->item(0)->getAttribute('NameQualifier')
                );
            }

            $subjectConfirmation = $xml->getElementsByTagName('SubjectConfirmation')->item(0);
            $subjectConfirmationData = $subjectConfirmation->getElementsByTagName('SubjectConfirmationData');
            if ($subjectConfirmationData->length == 0) {
                $logger->logAndThrow($xml, "Missing SubjectConfirmationData attribute");
            } elseif ($subjectConfirmationData->item(0)->getAttribute('InResponseTo') != $_SESSION['RequestID']) {
                $logger->logAndThrow(
                    $xml,
                    "Invalid SubjectConfirmationData attribute, expected {$_SESSION['RequestID']} but received " .
                    $subjectConfirmationData->item(0)->getAttribute('InResponseTo')
                );
            } elseif (strtotime($subjectConfirmationData->item(0)->getAttribute('NotOnOrAfter')) <= $minTime) {
                $logger->logAndThrow($xml, "Invalid NotOnOrAfter attribute");
            } elseif ($subjectConfirmationData->item(0)->getAttribute('Recipient') != $_SESSION['acsUrl']) {
                $logger->logAndThrow(
                    $xml,
                    "Invalid Recipient attribute, expected {$_SESSION['acsUrl']} but received " .
                    $subjectConfirmationData->item(0)->getAttribute('Recipient')
                );
            } elseif ($subjectConfirmation->getAttribute('Method') != $samlUrn . 'cm:bearer') {
                $logger->logAndThrow(
                    $xml,
                    "Invalid Method attribute, expected '{$samlUrn}cm:bearer' but received " .
                    $subjectConfirmation->getAttribute('Method')
                );
            }

            if ($xml->getElementsByTagName('Attribute')->length == 0) {
                $logger->logAndThrow($xml, "Missing Attribute Element");
            }

            if ($xml->getElementsByTagName('AttributeValue')->length == 0) {
                $logger->logAndThrow($xml, "Missing AttributeValue Element");
            }
        }

        $status = $xml->getElementsByTagName('Status');
        if ($status->length <= 0) {
            $logger->logAndThrow($xml, "Missing Status element");
        } elseif ($status->item(0) == null) {
            $logger->logAndThrow($xml, "Missing Status element");
        }

        $statusCode = $xml->getElementsByTagName('StatusCode');
        if ($statusCode->item(0) == null) {
            $logger->logAndThrow($xml, "Missing StatusCode element");
        } elseif ($statusCode->item(0)->getAttribute('Value') == $samlUrn . 'status:Success') {
            if ($hasAssertion && $xml->getElementsByTagName('AuthnStatement')->length <= 0) {
                $logger->logAndThrow($xml, "Missing AuthnStatement element");
            }
        } elseif ($statusCode->item(0)->getAttribute('Value') != $samlUrn . 'status:Success') {
            if ($xml->getElementsByTagName('StatusMessage')->item(0) != null) {
                $errorString = $xml->getElementsByTagName('StatusMessage')->item(0)->nodeValue;
                $logger->logAndThrow($xml, "StatusCode is not Success [message: {$errorString}]");
            } else {
                $logger->logAndThrow($xml, "StatusCode is not Success");
            }
        } elseif ($statusCode->item(1)->getAttribute('Value') == $samlUrn . 'status:AuthnFailed') {
            $logger->logAndThrow($xml, "AuthnFailed AuthnStatement element");
        } else {
            // Status code != success
            $logger->logAndThrow($xml, "Generic error");
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

    private function validateDate($date): bool
    {
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/', $date, $parts)) {
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

    private function spidSession(DOMDocument $xml): Session
    {
        $session = new Session();

        $attributes = [];
        $attributeStatements = $xml->getElementsByTagName('AttributeStatement');

        if ($attributeStatements->length > 0) {
            foreach ($attributeStatements->item(0)->childNodes as $attr) {
                if ($attr->hasAttributes()) {
                    $attributes[$attr->attributes->getNamedItem('Name')->nodeValue] = trim($attr->nodeValue);
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
