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

        if ($root->getAttribute('ID') == null || $root->getAttribute('ID') == "") {
            // Check response 8 on demo validator
            throw new \Exception("Missing ID attribute");
        }

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
        } elseif (strtotime($root->getAttribute('IssueInstant')) < strtotime('now') - $accepted_clock_skew_seconds) {
            // Check response 14 on demo validator
            throw new \Exception("IssueInstant attribute on Response is in the past");
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
                strtotime($root->getAttribute('IssueInstant'))) {
                    // The issueInstant of assertion have to compared with issueInstant of the response
                throw new \Exception("IssueInstant attribute on Assertion is in the future");
            } elseif (strtotime($xml->getElementsByTagName('Assertion')->item(0)->getAttribute('IssueInstant')) <
                strtotime($root->getAttribute('IssueInstant'))) { // Check response 39 on demo validator
                // The issueInstant of assertion have to compared with issueInstant of the response
                throw new \Exception("IssueInstant attribute on Assertion is in the past");
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
            
            if ($xml->getElementsByTagName('Subject')->length > 0) {
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
                        " but received " .
                        $xml->getElementsByTagName('NameID')->item(0)->getAttribute('NameQualifier'));
                }

                if ($xml->getElementsByTagName('SubjectConfirmation')->length > 0) {
                    if ($xml->getElementsByTagName('SubjectConfirmationData')->length == 0) {
                        throw new \Exception("Missing SubjectConfirmationData attribute");
                    } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->
                        getAttribute('InResponseTo') != $_SESSION['RequestID']) {
                        throw new \Exception("Invalid SubjectConfirmationData attribute, expected "
                            . $_SESSION['RequestID'] . " but received " .
                            $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->
                            getAttribute('InResponseTo'));
                    } elseif (strtotime(
                        $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('NotOnOrAfter')
                    ) <= strtotime('now') - $accepted_clock_skew_seconds) {
                        throw new \Exception("Invalid NotOnOrAfter attribute");
                    } elseif ($xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient')
                        != $_SESSION['acsUrl']) {
                        throw new \Exception("Invalid Recipient attribute, expected " . $_SESSION['acsUrl'] .
                            " but received " .
                            $xml->getElementsByTagName('SubjectConfirmationData')->item(0)->getAttribute('Recipient'));
                    } elseif ($xml->getElementsByTagName('SubjectConfirmation')->item(0)->getAttribute('Method') !=
                        'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
                        throw new \Exception("Invalid Method attribute, expected "
                            . "'urn:oasis:names:tc:SAML:2.0:cm:bearer' but received "
                            . $xml->getElementsByTagName('SubjectConfirmation')->item(0)->getAttribute('Method'));
                    }
                } else { // Check response 52 on demo validator
                    throw new \Exception("Missing SubjectConfirmation Element");
                }
            } else { // Check response 42 on demo validator
                throw new \Exception("Missing Subject Element");
            }

            if ($xml->getElementsByTagName('AuthnStatement')->length > 0) {
                // Check response 88 on demo validator
                if ($xml->getElementsByTagName('AuthnContext')->length == 0) {
                    // Check response 91 on demo validator
                    throw new \Exception("Missing AuthnContext element");
                } else {
                    // Check response 90 on demo validator
                    if ($xml->getElementsByTagName('AuthnContextClassRef')->length == 0) {
                        // Check response 93 on demo validator
                        throw new \Exception("Missing AuthnContextClassRef element");
                    } else {
                        $responseLevel = $xml->getElementsByTagName('AuthnContextClassRef')->item(0)->nodeValue;
                        $responseLevelInt = substr($responseLevel, -1);
                        if ($responseLevelInt >= 1 || $responseLevelInt <= 3) {
                            $len = strlen($responseLevel);
                            $responseLevelString = substr($responseLevel, -1 * (abs($len) + 1), -1);
                            if ($responseLevelString == "https://www.spid.gov.it/SpidL") {
                                if ($responseLevel != "https://www.spid.gov.it/SpidL".$_SESSION['level']) {
                                    // Checking response 97 on demo validator
                                    if ($_SESSION['comparison'] == 'exact') {
                                        throw new \Exception("AuthnContextClassRef value inconsistent");
                                    } else {
                                        if ($responseLevelInt > $_SESSION['level']) {
                                            if ($_SESSION['comparison'] == 'maximum') {
                                                throw new \Exception("AuthnContextClassRef value inconsistent");
                                            }
                                        }
                                        if ($responseLevelInt < $_SESSION['level']) {
                                            if ($_SESSION['comparison'] == 'minimum') {
                                                throw new \Exception("AuthnContextClassRef value inconsistent");
                                            }
                                        }
                                    }
                                }
                            } else { // Check response 92, 97 on demo validator
                                throw new \Exception("Invalid AuthnContextClassRef value");
                            }
                        } else { // Check response 97 on demo validator
                            throw new \Exception("Invalid AuthnContextClassRef value");
                        }
                    }
                }
            } else { // Check response 89 on demo validator
                throw new \Exception("Missing AuthnStatement Element");
            }

            if ($xml->getElementsByTagName('Attribute')->length == 0) {
                throw new \Exception("Missing Attribute Element");
            } else { // Check response 103 on demo validator
                $countRequestAttribute = 
                count($this->saml->settings['sp_attributeconsumingservice'][$_SESSION['assertID']]);
                $countResponseAttribute = count($xml->getElementsByTagName('Attribute'));
                if ($countRequestAttribute == $countResponseAttribute) {
                    // Check the parameter number requested are equal to the received ones
                    $isFound = false;
                    $arrayResponseAttribute = array();
                    foreach ($xml->getElementsByTagName('Attribute') as $responseAttribute) {
                        array_push($arrayResponseAttribute, $responseAttribute->getAttribute('Name'));
                    }
                    foreach ($this->saml->settings['sp_attributeconsumingservice'][$_SESSION['assertID']]
                    as &$requestAttribute) {
                        // Check the parameter received are the same requested
                        $isFound = array_search($requestAttribute, $arrayResponseAttribute, false);
                        if ($isFound === false) {
                            throw new \Exception("Missing attribute ".$requestAttribute);
                        } else {
                            $isFound = false;
                        }
                    }
                    unset($requestAttribute);
                } else {
                    throw new \Exception("Parameter number requested are not equal to the received ones");
                }
                
                if ($xml->getElementsByTagName('AttributeValue')->length == 0) {
                    throw new \Exception("Missing AttributeValue Element");
                }
            }
        } else { // Check response 32 on demo validator
            if ($xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') ==
            'urn:oasis:names:tc:SAML:2.0:status:Success') {
                throw new \Exception("Missing Assertion Element");
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
            if ($xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') !=
                'urn:oasis:names:tc:SAML:2.0:status:Requester' &&
                $xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') !=
                'urn:oasis:names:tc:SAML:2.0:status:Responder' &&
                $xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') !=
                'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch') {
                    throw new \Exception("StatusCode not valid");
            } else {
                if ($xml->getElementsByTagName('StatusMessage')->item(0) != null) {
                    $StatusMessage = ' [message: '
                    . $xml->getElementsByTagName('StatusMessage')->item(0)->nodeValue . ']';
                } else {
                    $StatusMessage = "";
                }
                throw new \Exception("StatusCode is not Success" . $StatusMessage);
            }
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
        unset($_SESSION['comparison']);
        unset($_SESSION['level']);
        unset($_SESSION['assertID']);
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
