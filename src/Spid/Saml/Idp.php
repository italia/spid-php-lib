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
        $metadata['idpEntityId'] = $xml->attributes()->entityID->__toString();
        $metadata['idpSSO'] = $xml->xpath('//md:SingleSignOnService')[0]->attributes()->Location->__toString();
        $metadata['idpSLO'] = $xml->xpath('//md:SingleLogoutService')[0]->attributes()->Location->__toString();
        $metadata['idpCertValue'] = $xml->xpath('//ds:X509Certificate')[0]->__toString();

        $this->idpFileName = $xmlFile;
        $this->metadata = $metadata;
        return $this;
    }

    public function authnRequest($ass, $attr, $redirectTo = null, $level = 1, $shouldRedirect = true)
    {
        $this->assertID = $ass;
        $this->attrID = $attr;
        $this->level = $level;

        $authn = new AuthnRequest($this);
        $url = $authn->redirectUrl($redirectTo);
        $_SESSION['RequestID'] = $authn->id;
        $_SESSION['idpName'] = $this->idpFileName;

        if (!$shouldRedirect)
        {
            return $url;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit(1);
    }

    public function logoutRequest(Session $session, $redirectTo = null)
    {
        $this->session = $session;
        $request = new LogoutRequest($this);
        $url = $request->redirectUrl($redirectTo);

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit();
    }
}
