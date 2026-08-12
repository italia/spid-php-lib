<?php

namespace Italia\Spid\Spid\Saml;

use Italia\Spid\Spid\Interfaces\IdpInterface;
use Italia\Spid\Spid\Saml\Out\AuthnRequest;
use Italia\Spid\Spid\Saml\Out\LogoutRequest;
use Italia\Spid\Spid\Session;
use Italia\Spid\Spid\Saml\Out\LogoutResponse;

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
        $safeName = basename($xmlFile);
        if (substr($safeName, -4) === '.xml') {
            $safeName = substr($safeName, 0, -4);
        }
        if ($safeName === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $safeName)) {
            throw new \Exception("Invalid Idp identifier '$xmlFile'. Only letters, digits, '-' and '_' are allowed.", 1);
        }

        $baseDir = realpath($this->sp->settings['idp_metadata_folder']);
        if ($baseDir === false) {
            throw new \Exception("Idp metadata folder does not exist or is not readable.", 1);
        }

        $candidate = $baseDir . DIRECTORY_SEPARATOR . $safeName . '.xml';
        $fileName = realpath($candidate);

        if ($fileName === false ||
            strncmp($fileName, $baseDir . DIRECTORY_SEPARATOR, strlen($baseDir) + 1) !== 0 ||
            !is_file($fileName)) {
            throw new \Exception("Metadata file for Idp '$safeName' not found", 1);
        }
        $xmlFile = $safeName;
        if (!file_exists($fileName)) {
            throw new \Exception("Metadata file $fileName not found", 1);
        }
        if (!is_readable($fileName)) {
            throw new \Exception("Metadata file $fileName is not readable. Please check file permissions.", 1);
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
        foreach ($xml->xpath('//md:SingleLogoutService') as $index => $item) {
            $idpSLO[$index]['location'] = $item->attributes()->Location->__toString();
            $idpSLO[$index]['binding'] = $item->attributes()->Binding->__toString();
        }

        $metadata['idpEntityId'] = $xml->attributes()->entityID->__toString();
        $metadata['idpSSO'] = $idpSSO;
        $metadata['idpSLO'] = $idpSLO;
        $metadata['idpCertValue'] = self::formatCert($xml->xpath('//ds:X509Certificate')[0]->__toString());

        $this->idpFileName = $xmlFile;
        $this->metadata = $metadata;
        return $this;
    }

    private static function formatCert($cert, $heads = true)
    {
        //$cert = str_replace(" ", "\n", $cert);
        $x509cert = str_replace(array("\x0D", "\r", "\n"), "", $cert);
        if (!empty($x509cert)) {
            $x509cert = str_replace('-----BEGIN CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace('-----END CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace(' ', '', $x509cert);

            if ($heads) {
                $x509cert = "-----BEGIN CERTIFICATE-----\n" .
                    chunk_split($x509cert, 64, "\n") .
                    "-----END CERTIFICATE-----\n";
            }
        }
        return $x509cert;
    }
    public function authnRequest($ass, $attr, $binding, $level = 1, $redirectTo = null, $shouldRedirect = true) : string
    {
        if (!in_array((int)$level, [1, 2, 3], true)) {
            throw new \Exception("Invalid SPID level requested: $level. Allowed values are 1, 2, 3.");
        }

        $this->assertID = $ass;
        $this->attrID = $attr;
        $this->level = $level;

        $authn = new AuthnRequest($this);
        $url = $binding == Settings::BINDING_REDIRECT ?
            $authn->redirectUrl($redirectTo) :
            $authn->httpPost($redirectTo);
        $_SESSION['RequestID'] = $authn->id;
        $_SESSION['idpName'] = $this->idpFileName;
        $_SESSION['idpEntityId'] = $this->metadata['idpEntityId'];
        $_SESSION['acsUrl'] = $this->sp->settings['sp_assertionconsumerservice'][$ass];
        $_SESSION['requestedAuthnLevel'] = (int)$level;
        $_SESSION['requestedAuthnComparison'] = isset($this->sp->settings['sp_comparison']) ?
            $this->sp->settings['sp_comparison'] : 'exact';

        if (!$shouldRedirect || $binding == Settings::BINDING_POST) {
            return $url;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }

    public function logoutRequest(Session $session, $slo, $binding, $redirectTo = null, $shouldRedirect = true) : string
    {
        $this->session = $session;

        $logoutRequest = new LogoutRequest($this);
        $url = ($binding == Settings::BINDING_REDIRECT) ?
            $logoutRequest->redirectUrl($redirectTo) :
            $logoutRequest->httpPost($redirectTo);

        $_SESSION['RequestID'] = $logoutRequest->id;
        $_SESSION['idpName'] = $this->idpFileName;
        $_SESSION['idpEntityId'] = $this->metadata['idpEntityId'];
        $_SESSION['sloUrl'] = reset($this->sp->settings['sp_singlelogoutservice'][$slo]);

        if (!$shouldRedirect || $binding == Settings::BINDING_POST) {
            return $url;
            exit;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }

    public function logoutResponse() : string
    {
        $binding = Settings::BINDING_POST;
        $redirectTo = $this->sp->settings['sp_entityid'];

        $logoutResponse = new LogoutResponse($this);
        $url = ($binding == Settings::BINDING_REDIRECT) ?
            $logoutResponse->redirectUrl($redirectTo) :
            $logoutResponse->httpPost($redirectTo);
        unset($_SESSION);
        
        if ($binding == Settings::BINDING_POST) {
            return $url;
            exit;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }
}
