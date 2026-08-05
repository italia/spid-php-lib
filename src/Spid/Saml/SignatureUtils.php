<?php

namespace Italia\Spid\Spid\Saml;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

class SignatureUtils
{
    public static function signXml($xml, $settings) : string
    {
        if (!is_readable($settings['sp_key_file'])) {
            throw new \Exception('Your SP key file is not readable. Please check file permissions.');
        }
        if (!is_readable($settings['sp_cert_file'])) {
            throw new \Exception('Your SP certificate file is not readable. Please check file permissions.');
        }
        $key = file_get_contents($settings['sp_key_file']);
        $key = openssl_get_privatekey($key, "");
        $cert = file_get_contents($settings['sp_cert_file']);
        $dom = new \DOMDocument();
        $dom->loadXML($xml);
    
        $objKey = new XMLSecurityKey('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', array('type' => 'private'));
        $objKey->loadKey($key, false);

        $rootNode = $dom->firstChild;
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objXMLSecDSig->addReferenceList(
            array($rootNode),
            'http://www.w3.org/2001/04/xmlenc#sha256',
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            array('id_name' => 'ID', 'overwrite' => false)
        );
        $objXMLSecDSig->sign($objKey);
        $objXMLSecDSig->add509Cert($cert, true);

        $insertBefore = $rootNode->firstChild;
        $messageTypes = array('AuthnRequest', 'Response', 'LogoutRequest', 'LogoutResponse');
        if (in_array($rootNode->localName, $messageTypes)) {
            $issuerNodes = self::query($dom, '/' . $rootNode->tagName . '/saml:Issuer');
            if ($issuerNodes->length == 1) {
                $insertBefore = $issuerNodes->item(0)->nextSibling;
            }
        }
        $objXMLSecDSig->insertSignature($rootNode, $insertBefore);

        return $dom->saveXML();
    }

    public static function signUrl($samlRequest, $relayState, $signatureAlgo, $keyFile)
    {
        if (!is_readable($keyFile)) {
            throw new \Exception('Your SP key file is not readable. Please check file permissions.');
        }
        $key = file_get_contents($keyFile);
        $key = openssl_get_privatekey($key, "");

        $msg = "SAMLRequest=" . rawurlencode($samlRequest);
        if (isset($relayState)) {
            $msg .= "&RelayState=" . rawurlencode($relayState);
        }
        $msg .= "&SigAlg=" . rawurlencode($signatureAlgo);

        openssl_sign($msg, $signature, $key, "SHA256");
        return base64_encode($signature);
    }

    // Validates the signature node $xml against the trusted certificate $cert.
    //
    // $xml is the <ds:Signature> element; the element it is meant to protect is
    // its parent (the Response root or the Assertion). The signature is checked
    // against ONLY that element, copied on its own into a fresh document, so that
    // no other node elsewhere in the response can be substituted for the signed
    // one. This closes the SAML signature wrapping (XSW) class of attacks, where
    // a forged, unsigned assertion is smuggled next to the genuine signed one and
    // the rest of the library ends up reading the forged copy
    // (CWE-347, CWE-349, CWE-290).
    public static function validateXmlSignature($xml, $cert) : bool
    {
        if (is_null($xml)) {
            return true;
        }

        $signedNode = $xml->parentNode;
        if (is_null($signedNode)) {
            return false;
        }

        // Copy the signed element, and only that element, into an isolated
        // document. locateSignature() below then cannot pick a signature that
        // lives somewhere else in the original response, and validateReference()
        // can only resolve references that stay inside this subtree.
        $dom = new \DOMDocument();
        $dom->appendChild($dom->importNode($signedNode, true));

        $x509 = $dom->getElementsByTagName('X509Certificate')->item(0);
        if (is_null($x509)) {
            return false;
        }
        $certFingerprint = Settings::cleanOpenSsl($cert, true);
        $signCertFingerprint = Settings::cleanOpenSsl($x509->nodeValue, true);
        if ($signCertFingerprint != $certFingerprint) {
            return false;
        }

        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = array('ID');

        $objDSig = $objXMLSecDSig->locateSignature($dom);
        if (is_null($objDSig)) {
            return false;
        }
        $objKey = $objXMLSecDSig->locateKey();
        if (is_null($objKey)) {
            return false;
        }

        $objXMLSecDSig->canonicalizeSignedInfo();

        try {
            if (!$objXMLSecDSig->validateReference()) {
                return false;
            }
        } catch (\Exception $e) {
            // A wrapped or tampered reference throws here: fail closed.
            return false;
        }

        // The signature must actually cover the element it is attached to, not a
        // nested node smuggled inside it: the enclosing element has to be among
        // the nodes whose digest was just validated.
        if (!self::signatureCoversNode($objXMLSecDSig, $dom->documentElement)) {
            return false;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

        $objKey->loadKey($cert, false, true);
        return $objXMLSecDSig->verify($objKey) === 1;
    }

    // Confirms that $node (the signed element) is one of the references the
    // signature validated. Without this check a signature whose Reference points
    // at a wrapped child element would still be accepted while the surrounding
    // element it is attached to stays unsigned.
    private static function signatureCoversNode(XMLSecurityDSig $objXMLSecDSig, \DOMNode $node) : bool
    {
        $validatedNodes = $objXMLSecDSig->getValidatedNodes();
        if (!is_array($validatedNodes)) {
            return false;
        }
        foreach ($validatedNodes as $validated) {
            if ($validated instanceof \DOMDocument) {
                $validated = $validated->documentElement;
            }
            if ($validated instanceof \DOMNode && $validated->isSameNode($node)) {
                return true;
            }
        }
        return false;
    }

    public static function certDNEquals($cert, $settings)
    {
        $parsed = openssl_x509_parse($cert);
        $dn = $parsed['subject'];

        $newDN = array();
        $newDN[] = $settings['sp_org_name'] ?? [];
        $newDN[] = $settings['sp_org_display_name'] ?? [];
        $newDN = array_merge($newDN, $settings['sp_key_cert_values'] ?? []);
        asort($dn);
        asort($newDN);

        if (array_values($dn) == array_values($newDN)) {
            return true;
        }
        return false;
    }

    public static function generateKeyCert($settings) : array
    {
        $numberofdays = 3652 * 2;
        $privkey = openssl_pkey_new(array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ));
        $dn = array(
            "countryName" => $settings['sp_key_cert_values']['countryName'],
            "stateOrProvinceName" => $settings['sp_key_cert_values']['stateOrProvinceName'],
            "localityName" => $settings['sp_key_cert_values']['localityName'],
            "organizationName" => $orgName = $settings['sp_org_name'],
            "organizationalUnitName" => $settings['sp_org_display_name'],
            "commonName" => $settings['sp_key_cert_values']['commonName'],
            "emailAddress" => $settings['sp_key_cert_values']['emailAddress']
        );
        $csr = openssl_csr_new($dn, $privkey, array('digest_alg' => 'sha256'));
        // eight random bytes overflow PHP_INT_MAX about half of the time, so casting the
        // resulting float back to int silently truncated the serial number; on PHP 8.5 the
        // same cast raises "The float ... is not representable as an int, cast occurred"
        $myserial = random_int(1, PHP_INT_MAX);
        $configArgs = array("digest_alg" => "sha256");
        $sscert = openssl_csr_sign($csr, null, $privkey, $numberofdays, $configArgs, $myserial);
        openssl_x509_export($sscert, $publickey);
        openssl_pkey_export($privkey, $privatekey);
        return [
            'key' => $privatekey,
            'cert' => $publickey
        ];
    }

    private static function query(\DOMDocument $dom, $query, ?\DOMElement $context = null)
    {
        $xpath = new \DOMXPath($dom);

        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $xpath->registerNamespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $xpath->registerNamespace('xs', 'http://www.w3.org/2001/XMLSchema');
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        if (isset($context)) {
            $res = $xpath->query($query, $context);
        } else {
            $res = $xpath->query($query);
        }
        return $res;
    }
}
