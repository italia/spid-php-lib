<?php

namespace Italia\Spid\Spid\Saml;

class SignatureUtils
{
    public static function signXml($xml, $settings) : stirng
    {
        $key = file_get_contents($settings['sp_key_file']);
        $key = openssl_get_privatekey($key, "");
        $cert = file_get_contents($settings['sp_cert_file']);
        $dom = new \DOMDocument();
        $dom->loadXML($xml);
        if (!$dom) {
            throw new Exception('Error parsing xml string');
        }

        $objKey = new XMLSecurityKey('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', array('type' => 'private'));
        $objKey->loadKey($key, false);

        $rootNode = $dom->firstChild;
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objXMLSecDSig->addReferenceList(
            array($rootNode),
            'http://www.w3.org/2001/04/xmlenc#sha256',
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            array('id_name' => 'ID')
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
}
