<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\RequestInterface;
use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\Settings;
use Italia\Spid\Spid\Saml\SignatureUtils;

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

    public function redirect($url, $redirectTo = null)
    {
        $compressed = gzdeflate($this->xml);
        $parameters['SAMLRequest'] = base64_encode($compressed);
        $parameters['RelayState'] = is_null($redirectTo) ? (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "//{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}" : $redirectTo;
        $parameters['SigAlg'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        $parameters['Signature'] = SignatureUtils::signUrl($parameters['SAMLRequest'], $parameters['RelayState'], $parameters['SigAlg'], $this->idp->sp->settings['sp_key_file']);
        $query = http_build_query($parameters);
        $url .= '?' . $query;
        return $url;
    }
}
