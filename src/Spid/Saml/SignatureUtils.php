<?php

namespace Italia\Spid\Spid\Saml;

use DOMDocument;
use DOMXPath;
use Exception;
use Italia\Spid\Spid\Interfaces\LoggerSelector;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SignatureUtils
{
    /**
     * @throws Exception
     */
    public static function signXml($xml, $settings): string
    {
        if (!is_readable($settings['sp_key_file'])) {
            throw new Exception('Your SP key file is not readable. Please check file permissions.');
        }
        if (!is_readable($settings['sp_cert_file'])) {
            throw new Exception('Your SP certificate file is not readable. Please check file permissions.');
        }
        $key = file_get_contents($settings['sp_key_file']);
        $key = openssl_get_privatekey($key, "");
        $cert = file_get_contents($settings['sp_cert_file']);
        $dom = new DOMDocument();
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
            $issuerNodes = self::query($dom, '/' . $rootNode->localName . '/saml:Issuer');
            if ($issuerNodes->length == 1) {
                $insertBefore = $issuerNodes->item(0)->nextSibling;
            }
        }
        $objXMLSecDSig->insertSignature($rootNode, $insertBefore);

        return $dom->saveXML();
    }

    /**
     * @throws Exception
     */
    public static function signUrl($samlRequest, $relayState, $signatureAlgo, $keyFile): string
    {
        if (!is_readable($keyFile)) {
            throw new Exception('Your SP key file is not readable. Please check file permissions.');
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

    /**
     * @throws Exception
     */
    public static function validateXmlSignature($xml, $cert, LoggerSelector $logger): bool
    {
        if (is_null($xml)) {
            return true;
        }
        $dom = clone $xml->ownerDocument;

        $certFingerprint = Settings::cleanOpenSsl($cert, true);
        $signCertFingerprint = Settings::cleanOpenSsl(
            $dom->getElementsByTagName('X509Certificate')->item(0)->nodeValue,
            true
        );
        if ($signCertFingerprint != $certFingerprint) {
            $logger = $logger->getTemporaryLogger();
            if ($logger) {
                $errorMessage = <<<LOG
Invalid certificate fingerprint:
 - signCertFingerPrint: {signCertFingerprint}
 - certFingerPrint: {certFingerprint}
LOG;

                $logger->error($errorMessage, [
                    'signCertFingerprint' => var_export($signCertFingerprint, true),
                    'certFingerprint' => var_export($certFingerprint, true)
                ]);
            }
            return false;
        }

        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = array('ID');

        $objDSig = $objXMLSecDSig->locateSignature($dom);
        $objKey = $objXMLSecDSig->locateKey();

        $objXMLSecDSig->canonicalizeSignedInfo();

        $objXMLSecDSig->validateReference();

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

        $objKey->loadKey($cert, false, true);
        if ($objXMLSecDSig->verify($objKey) === 1) {
            return true;
        }
        return false;
    }

    public static function certDNEquals($cert, $settings): bool
    {
        $parsed = openssl_x509_parse($cert);
        $dn = $parsed['subject'];

        $newDN = [];
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

    public static function generateKeyCert($settings): array
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
            "organizationName" => $settings['sp_org_name'],
            "organizationalUnitName" => $settings['sp_org_display_name'],
            "commonName" => $settings['sp_key_cert_values']['commonName'],
            "emailAddress" => $settings['sp_key_cert_values']['emailAddress']
        );
        $csr = openssl_csr_new($dn, $privkey, array('digest_alg' => 'sha256'));
        $myserial = (int) hexdec(bin2hex(openssl_random_pseudo_bytes(8)));
        $configArgs = array("digest_alg" => "sha256");
        $sscert = openssl_csr_sign($csr, null, $privkey, $numberofdays, $configArgs, $myserial);
        openssl_x509_export($sscert, $publicKey);
        openssl_pkey_export($privkey, $privateKey);
        return [
            'key' => $privateKey,
            'cert' => $publicKey
        ];
    }

    private static function query(DOMDocument $dom, $query)
    {
        $xpath = new DOMXPath($dom);

        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $xpath->registerNamespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $xpath->registerNamespace('xs', 'http://www.w3.org/2001/XMLSchema');
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        return $xpath->query($query);
    }
}
