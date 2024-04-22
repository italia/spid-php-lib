<?php

namespace Italia\Spid\Spid\Saml;

use Exception;
use Italia\Spid\Sp;
use Italia\Spid\Spid\Interfaces\IdpInterface;
use Italia\Spid\Spid\Saml;
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

    /**
     * @param Saml|Sp $sp
     */
    public function __construct($sp)
    {
        $this->sp = $sp;
    }

    /**
     * @throws Exception
     */
    public function loadFromXml($xmlFile): self
    {
        if (strpos($xmlFile, $this->sp->settings['idp_metadata_folder']) !== false) {
            $fileName = $xmlFile;
        } else {
            $fileName = $this->sp->settings['idp_metadata_folder'] . $xmlFile . ".xml";
        }
        if (!file_exists($fileName)) {
            throw new Exception("Metadata file $fileName not found", 1);
        }
        if (!is_readable($fileName)) {
            throw new Exception("Metadata file $fileName is not readable. Please check file permissions.", 1);
        }
        $xml = simplexml_load_file($fileName);

        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $metadata = [];
        $idpSSO = [];
        foreach ($xml->xpath('//md:SingleSignOnService') as $index => $item) {
            $idpSSO[$index]['location'] = $item->attributes()->Location->__toString();
            $idpSSO[$index]['binding'] = $item->attributes()->Binding->__toString();
        }

        $idpSLO = [];
        foreach ($xml->xpath('//md:SingleLogoutService') as $index => $item) {
            $idpSLO[$index]['location'] = $item->attributes()->Location->__toString();
            $idpSLO[$index]['binding'] = $item->attributes()->Binding->__toString();
        }

        $metadata['idpEntityId'] = $xml->attributes()->entityID->__toString();
        $metadata['idpSSO'] = $idpSSO;
        $metadata['idpSLO'] = $idpSLO;
        $excludedIdps =
            (strpos($metadata['idpEntityId'], 'lepida') != false) ||
            (strpos($metadata['idpEntityId'], 'tim') != false) ||
            (strpos($metadata['idpEntityId'], 'posteid') != false);

        if ($excludedIdps) {
            $metadata['idpCertValue'] = self::formatCert($xml->xpath('//ds:X509Certificate')[0]->__toString());
        } else {
            $metadata['idpCertValue'] = self::formatCert(
                $xml->xpath('//md:IDPSSODescriptor//ds:X509Certificate')[0]->__toString()
            );
        }

        $this->idpFileName = $xmlFile;
        $this->metadata = $metadata;
        return $this;
    }

    private static function formatCert($cert)
    {
        //$cert = str_replace(" ", "\n", $cert);
        $x509cert = str_replace(array("\x0D", "\r", "\n"), "", $cert);
        if (!empty($x509cert)) {
            $x509cert = str_replace('-----BEGIN CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace('-----END CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace(' ', '', $x509cert);
            $x509cert = "-----BEGIN CERTIFICATE-----\n" .
                chunk_split($x509cert, 64, "\n") .
                "-----END CERTIFICATE-----\n";
        }
        return $x509cert;
    }

    /**
     * @throws Exception
     */
    public function authnRequest($ass, $attr, $binding, $level = 1, $redirectTo = null, $shouldRedirect = true): string
    {
        $this->assertID = $ass;
        $this->attrID = $attr;
        $this->level = $level;

        $authn = new AuthnRequest($this, $this->sp->getLogger());
        $url = $binding == Settings::BINDING_REDIRECT ?
            $authn->redirectUrl($redirectTo) :
            $authn->httpPost($redirectTo);

        $_SESSION['RequestID'] = $authn->id;
        $_SESSION['idpName'] = $this->idpFileName;
        $_SESSION['idpEntityId'] = $this->metadata['idpEntityId'];
        $_SESSION['acsUrl'] = $this->sp->settings['sp_assertionconsumerservice'][$ass];

        if (!$shouldRedirect || $binding == Settings::BINDING_POST) {
            return $url;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }

    /**
     * @throws Exception
     */
    public function logoutRequest(Session $session, $slo, $binding, $redirectTo = null, $shouldRedirect = true): string
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

    /**
     * @throws Exception
     */
    public function logoutResponse(): string
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
