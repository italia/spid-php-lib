<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\Settings;

class Base
{
    public $idp;
    public $xml;
    public $id;
    public $issueInstant;

    public function __construct(Idp $idp)
    {
        $this->idp = $idp;
    }

    public function generateID()
    {
        $this->id = '_' . bin2hex(random_bytes(16));
        return $this->id;
    }

    public function generateIssueInstant()
    {
        $this->issueInstant = gmdate('Y-m-d\TH:i:s\Z');
        return $this->issueInstant;
    }

    public function redirectUrl($url, $redirectTo = null)
    {
        $compressed = gzdeflate($this->xml);
        $parameters['SAMLRequest'] = base64_encode($compressed);
        $parameters['RelayState'] = is_null($redirectTo) ? (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "//{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}" : $redirectTo;
        $parameters['SigAlg'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        $parameters['Signature'] = $this->buildUrlSignature($parameters['SAMLRequest'], $parameters['RelayState'], $parameters['SigAlg']);
        $query = http_build_query($parameters);
        $url .= '?' . $query;
        return $url;
    }

    public function buildXmlSignature($ref)
    {
        $cert = Settings::cleanOpenSsl($this->idp->settings['sp_cert_file']);

        $signatureXml = <<<XML
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
  <ds:Reference URI="#$ref">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
    <ds:DigestValue></ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue></ds:SignatureValue>
<ds:KeyInfo>
  <ds:X509Data>
    <ds:X509Certificate>$cert</ds:X509Certificate>
  </ds:X509Data>
</ds:KeyInfo>
</ds:Signature>
XML;
        return $signatureXml;
    }

    public function buildUrlSignature($samlRequest, $relayState, $signatureAlgo)
    {
        $key = file_get_contents($this->idp->settings['sp_key_file']);

        //$key = Settings::cleanOpenSsl($this->idp->settings['sp_key_file']);
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
