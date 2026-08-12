<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Interfaces\ResponseInterface;
use Italia\Spid\Spid\Session;
use Italia\Spid\Spid\Saml;

class Response implements ResponseInterface
{
    const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
    const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

    // The only AuthnContextClassRef values a SPID IdP may assert, and the level
    // each one stands for.
    const SPID_LEVELS = [
        'https://www.spid.gov.it/SpidL1' => 1,
        'https://www.spid.gov.it/SpidL2' => 2,
        'https://www.spid.gov.it/SpidL3' => 3,
    ];

    private $saml;

    public function __construct(Saml $saml)
    {
        $this->saml = $saml;
    }

    public function validate($xml, $assertion): bool
    {
        $accepted_clock_skew_seconds = isset($this->saml->settings['accepted_clock_skew_seconds']) ?
            $this->saml->settings['accepted_clock_skew_seconds'] : 0;

        $root = $xml->documentElement;

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

        // The Issuer of the message itself, read as a direct child of the root so
        // that no nested copy can be mistaken for it.
        $responseIssuer = $this->query($root, './saml:Issuer')->item(0);
        if (is_null($responseIssuer)) {
            throw new \Exception("Missing Issuer attribute");
        } elseif ($responseIssuer->nodeValue != $_SESSION['idpEntityId']) {
            throw new \Exception("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] .
                " but received " . $responseIssuer->nodeValue);
        } elseif ($responseIssuer->getAttribute('Format') !=
            'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
            throw new \Exception("Invalid Issuer attribute, expected 'urn:oasis:names:tc:SAML:2.0:nameid-format:" .
                "entity'" . " but received " . $responseIssuer->getAttribute('Format'));
        }

        if (!is_null($assertion)) {
            if ($assertion->getAttribute('ID') == "" ||
                $assertion->getAttribute('ID') == null) {
                throw new \Exception("Missing ID attribute on Assertion");
            } elseif ($assertion->getAttribute('Version') != '2.0') {
                throw new \Exception("Invalid Version attribute on Assertion");
            } elseif ($assertion->getAttribute('IssueInstant') == "") {
                throw new \Exception("Invalid IssueInstant attribute on Assertion");
            } elseif (!$this->validateDate($assertion->getAttribute('IssueInstant'))) {
                throw new \Exception("Invalid IssueInstant attribute on Assertion");
            } elseif (strtotime($assertion->getAttribute('IssueInstant')) >
                strtotime('now') + $accepted_clock_skew_seconds) {
                throw new \Exception("IssueInstant attribute on Assertion is in the future");
            }

            // The Issuer of the assertion, again as a direct child of the element
            // it belongs to rather than by position in a document wide list.
            $assertionIssuer = $this->query($assertion, './saml:Issuer')->item(0);
            if (is_null($assertionIssuer)) {
                throw new \Exception("Missing Issuer element on Assertion");
            } elseif ($assertionIssuer->nodeValue != $_SESSION['idpEntityId']) {
                throw new \Exception("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] .
                    " but received " . $assertionIssuer->nodeValue);
            } elseif ($assertionIssuer->getAttribute('Format') !=
                'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') {
                throw new \Exception("Invalid Issuer attribute, expected 'urn:oasis:names:tc:SAML:2.0:nameid-format:" .
                "entity'" . " but received " . $assertionIssuer->getAttribute('Format'));
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
            // A successful Response always carries a validated assertion: BaseResponse
            // refuses one that does not, so reaching here without it is impossible.
            if (is_null($assertion)) {
                throw new \Exception("Missing Assertion element");
            }
            if ($xml->getElementsByTagName('AuthnStatement')->length <= 0) {
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
        $level = $this->validateLevel($assertion);
        $session = $this->spidSession($assertion, $level);

        // Session fixation: the identifier used while unauthenticated must not
        // carry over into the authenticated session. Regenerating it before the
        // authenticated state is written means the old identifier never holds it.
        if (session_status() === PHP_SESSION_ACTIVE && !headers_sent()) {
            session_regenerate_id(true);
        }

        $_SESSION['spidSession'] = (array)$session;
        unset($_SESSION['RequestID']);
        unset($_SESSION['idpName']);
        unset($_SESSION['idpEntityId']);
        unset($_SESSION['acsUrl']);
        unset($_SESSION['requestedLevel']);
        unset($_SESSION['requestedComparison']);
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

    // The level the IdP actually asserted has to be a real SPID level, and it has
    // to satisfy the level the SP asked for. Deriving it from the last character of
    // the AuthnContextClassRef accepted any URI that happened to end with the right
    // digit, and the value was never compared with the requested level at all, so
    // an IdP could answer SpidL1 to a request for SpidL2 and be believed.
    private function validateLevel(\DOMElement $assertion) : int
    {
        $refs = $this->query($assertion, './saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef');
        if ($refs->length != 1) {
            throw new \Exception("Invalid Response. Exactly one AuthnContextClassRef is required, found " .
                $refs->length);
        }
        $uri = trim($refs->item(0)->nodeValue);
        if (!array_key_exists($uri, self::SPID_LEVELS)) {
            throw new \Exception("Invalid Response. Unknown AuthnContextClassRef " . $uri);
        }
        $returned = self::SPID_LEVELS[$uri];

        if (!isset($_SESSION['requestedLevel'])) {
            // No requested level was recorded for this transaction, so the session
            // was not opened through this library's login(). The asserted URI has
            // still been checked against the allowed set; there is simply nothing
            // to compare it against.
            return $returned;
        }
        $requested = (int)$_SESSION['requestedLevel'];
        $comparison = $_SESSION['requestedComparison'] ?? 'exact';
        if (!$this->levelSatisfies($returned, $requested, $comparison)) {
            throw new \Exception("Invalid Response. The Identity Provider returned SPID level " . $returned .
                ", which does not satisfy the requested level " . $requested .
                " with comparison " . $comparison);
        }
        return $returned;
    }

    // SAML 2.0 core, RequestedAuthnContext/@Comparison semantics.
    private function levelSatisfies(int $returned, int $requested, string $comparison) : bool
    {
        switch ($comparison) {
            case 'minimum':
                return $returned >= $requested;
            case 'better':
                return $returned > $requested;
            case 'maximum':
                return $returned <= $requested;
            case 'exact':
            default:
                return $returned === $requested;
        }
    }

    // Builds the authenticated session out of the validated assertion only. Reading
    // the whole document here is what made a forged element planted outside the
    // assertion end up in the session.
    private function spidSession(\DOMElement $assertion, int $level)
    {
        $session = new Session();

        $attributes = array();
        foreach ($this->query($assertion, './saml:AttributeStatement/saml:Attribute') as $attr) {
            $name = $attr->getAttribute('Name');
            if ($name === '') {
                continue;
            }
            $attributes[$name] = trim($attr->nodeValue);
        }

        $session->sessionID = $_SESSION['RequestID'];
        $session->idp = $_SESSION['idpName'];
        // Validated above against the Issuer of both the message and the assertion.
        $session->idpEntityID = $_SESSION['idpEntityId'];
        $session->attributes = $attributes;
        $session->level = $level;
        return $session;
    }

    // Namespace aware lookup, evaluated relative to $context so that a result can
    // only ever come from inside the element it is meant to describe.
    private function query(\DOMElement $context, string $path)
    {
        $xpath = new \DOMXPath($context->ownerDocument);
        $xpath->registerNamespace('saml', self::NS_SAML);
        $xpath->registerNamespace('samlp', self::NS_SAMLP);
        return $xpath->query($path, $context);
    }
}
