<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Saml\Idp;
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
        $parameters['RelayState'] = is_null($redirectTo) ? (isset($_SERVER['HTTPS'])
            && $_SERVER['HTTPS'] === 'on' ? "https" : "http") .
            "//{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}" : $redirectTo;
        $parameters['SigAlg'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        $parameters['Signature'] = SignatureUtils::signUrl(
            $parameters['SAMLRequest'],
            $parameters['RelayState'],
            $parameters['SigAlg'],
            $this->idp->sp->settings['sp_key_file']
        );
        $query = http_build_query($parameters);
        $url .= '?' . $query;
        return $url;
    }

    public function postForm($url, $redirectTo = null)
    {
        $SAMLRequest = base64_encode($this->xml);

        $relayState = is_null($redirectTo) ? (isset($_SERVER['HTTPS']) &&
            $_SERVER['HTTPS'] === 'on' ? "https" : "http") .
            "//{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}" : $redirectTo;
        $relayState = null;
        return <<<HTML
<html>
    <body onload="javascript:document.forms[0].submit()">
        <form method="post" action="$url">
            <input type="hidden" name="SAMLRequest" value="$SAMLRequest">
            <input type="hidden" name="RelayState" value="$relayState">
        </form>
    </body>
</html>
HTML;
    }

    protected function getBindingLocation($binding, $service = 'SSO')
    {
        $location = null;
        $key = 'idp' . $service;
        array_walk($this->idp->metadata[$key], function ($val) use ($binding, &$location) {
            if ($binding == $val['binding']) {
                $location = $val['location'];
            }
        });
        if (is_null($location)) {
            throw new \Exception("No location found for binding " . $binding);
        }
        return $location;
    }
}
