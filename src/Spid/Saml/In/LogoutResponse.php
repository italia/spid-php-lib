<?php

namespace Italia\Spid\Spid\Saml\In;

use DOMDocument;
use Exception;
use Italia\Spid\Spid\Interfaces\ResponseInterface;

class LogoutResponse implements ResponseInterface
{
    /**
     * @throws Exception
     */
    public function validate(DOMDocument $xml, $hasAssertion): bool
    {
        $root = $xml->getElementsByTagName('LogoutResponse')->item(0);

        if ($root->getAttribute('ID') == "") {
            throw new Exception("missing ID attribute");
        }
        if ($root->getAttribute('Version') == "") {
            throw new Exception("missing Version attribute");
        } elseif ($root->getAttribute('Version') != '2.0') {
            throw new Exception("Invalid Version attribute");
        }
        if ($root->getAttribute('IssueInstant') == "") {
            throw new Exception("Missing IssueInstant attribute");
        }
        if ($root->getAttribute('InResponseTo') == "" || !isset($_SESSION['RequestID'])) {
            throw new Exception("Missing InResponseTo attribute, or request ID was not saved correctly " .
                "for comparison");
        } elseif ($root->getAttribute('InResponseTo') != $_SESSION['RequestID']) {
            throw new Exception("Invalid InResponseTo attribute, expected " . $_SESSION['RequestID']);
        }
        if ($root->getAttribute('Destination') == "") {
            throw new Exception("Missing Destination attribute");
        } elseif ($root->getAttribute('Destination') != $_SESSION['sloUrl']) {
            throw new Exception("Invalid Destination attribute, expected " . $_SESSION['sloUrl'] .
                " but received " . $root->getAttribute('Destination'));
        }
        if ($xml->getElementsByTagName('Issuer')->length == 0) {
            throw new Exception("Missing Issuer attribute");
        } elseif ($xml->getElementsByTagName('Issuer')->item(0)->nodeValue != $_SESSION['idpEntityId']) {
            throw new Exception("Invalid Issuer attribute, expected " . $_SESSION['idpEntityId'] .
                " but received " . $xml->getElementsByTagName('Response')->item(0)->nodeValue);
        }
        if ($xml->getElementsByTagName('Status')->length <= 0) {
            throw new Exception("Missing Status element");
        } elseif (
            $xml->getElementsByTagName('StatusCode')->item(0)->getAttribute('Value') !=
            'urn:oasis:names:tc:SAML:2.0:status:Success'
        ) {
            // Status code != success
            return false;
        }
        session_unset();
        return true;
    }
}
