<?php

namespace Italia\Spid\Spid\Saml;

use Italia\Spid\Spid\Interfaces\IdpInterface;
use Italia\Spid\Spid\Saml\Out\AuthnRequest;
use Italia\Spid\Spid\Saml\Out\LogoutRequest;
use Italia\Spid\Spid\Session;

class Idp implements IdpInterface
{
    public $idpFileName;
    public $metadata;
    public $sp;
    public $assertID;
    public $attrID;
    public $level = 1;
    public $session;

    public function __construct($sp)
    {
        $this->sp = $sp;
    }

    public function loadFromXml($xmlFile)
    {
        $fileName = $this->sp->settings['idp_metadata_folder'] . $xmlFile . ".xml";
        if (!file_exists($fileName)) {
            throw new \Exception("Metadata file $fileName not found", 1);
        }

        $xml = simplexml_load_file($fileName);

        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $metadata = array();
        $idpSSO = array();
        foreach ($xml->xpath('//md:SingleSignOnService') as $index => $item) {
            $idpSSO[$index]['location'] = $item->attributes()->Location->__toString();
            $idpSSO[$index]['binding'] = $item->attributes()->Binding->__toString();
        }

        $idpSLO = array();
        foreach ($xml->xpath('//md:SingleLogoutService') as $item) {
            $idpSLO[$index]['location'] = $item->attributes()->Location->__toString();
            $idpSLO[$index]['binding'] = $item->attributes()->Binding->__toString();
        }

        $metadata['idpEntityId'] = $xml->attributes()->entityID->__toString();
        $metadata['idpSSO'] = $idpSSO;
        $metadata['idpSLO'] = $idpSLO;
        $metadata['idpCertValue'] = $xml->xpath('//ds:X509Certificate')[0]->__toString();

        $this->idpFileName = $xmlFile;
        $this->metadata = $metadata;
        return $this;
    }

    public function authnRequest($ass, $attr, $binding, $level = 1, $redirectTo = null, $shouldRedirect = true) : string
    {
        $this->assertID = $ass;
        $this->attrID = $attr;
        $this->level = $level;

        $authn = new AuthnRequest($this);
        $url = $binding == Settings::BINDING_REDIRECT ? $authn->redirectUrl($redirectTo) : $authn->httpPost($redirectTo);
        $_SESSION['RequestID'] = $authn->id;
        $_SESSION['idpName'] = $this->idpFileName;

        if (!$shouldRedirect || $binding == Settings::BINDING_POST) {
            return $url;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }

    public function logoutRequest(Session $session, $binding, $redirectTo = null, $shouldRedirect = true) : string
    {
        $this->session = $session;

        $logoutRequest = new LogoutRequest($this);
        $url = $binding == Settings::BINDING_REDIRECT ? $logoutRequest->redirectUrl($redirectTo) : $logoutRequest->httpPost($redirectTo);
        $_SESSION['RequestID'] = $logoutRequest->id;
        $_SESSION['idpName'] = $logoutRequest->idpFileName;

        if (!$shouldRedirect || $binding == Settings::BINDING_POST) {
            return $url;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }
}
