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
        $identifier = $this->idpIdentifier($xmlFile);
        $fileName = $this->metadataFile($identifier);
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

        $this->idpFileName = $identifier;
        $this->metadata = $metadata;
        return $this;
    }

    // Reduces whatever the caller passed to the bare name of an Identity Provider.
    //
    // The certificate found in this metadata is the trust anchor used later to
    // validate the SAML Response, so whoever chooses the file chooses who may
    // authenticate users. The previous implementation used the value as a file name
    // as soon as it contained the configured folder anywhere inside it, which let a
    // caller pass an absolute path, a traversal, a URL or a PHP stream wrapper and
    // supply their own metadata, and therefore their own signing certificate.
    // Any directory component is dropped here on purpose: an Identity Provider is
    // named, never located, by the caller.
    private function idpIdentifier($xmlFile) : string
    {
        if (!is_string($xmlFile) || $xmlFile === '' || strpos($xmlFile, "\0") !== false) {
            throw new \Exception("Invalid Identity Provider identifier", 1);
        }
        // No URL and no PHP stream wrapper, whatever the rest of the value looks
        // like: metadata is read from the local metadata folder, never fetched.
        if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', $xmlFile) === 1) {
            throw new \Exception("Invalid Identity Provider identifier: a URL is not accepted", 1);
        }

        $normalized = str_replace('\\', '/', $xmlFile);
        if (strpos($normalized, '/') !== false) {
            // A path was supplied rather than a bare name. It is honoured only when
            // it genuinely points at a file sitting directly in the configured
            // folder, which is what getIdpList() passes; anything else, traversal
            // and symbolic links out of the folder included, is refused here.
            $folder = realpath($this->sp->settings['idp_metadata_folder']);
            $resolved = realpath($normalized);
            if ($folder === false || $resolved === false ||
                dirname($resolved) !== $folder || !is_file($resolved)
            ) {
                throw new \Exception("Invalid Identity Provider identifier: " .
                    "the metadata path is outside the configured folder", 1);
            }
        }

        $identifier = basename($normalized, '.xml');
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*$/', $identifier) || strpos($identifier, '..') !== false) {
            throw new \Exception("Invalid Identity Provider identifier", 1);
        }
        return $identifier;
    }

    // Resolves the identifier to a regular, readable file proven to sit directly
    // inside the configured metadata folder, symbolic links included.
    private function metadataFile(string $identifier) : string
    {
        $folder = realpath($this->sp->settings['idp_metadata_folder']);
        if ($folder === false) {
            throw new \Exception("The configured idp_metadata_folder does not exist", 1);
        }
        $fileName = realpath($folder . DIRECTORY_SEPARATOR . $identifier . '.xml');
        if ($fileName === false) {
            throw new \Exception("Metadata file $identifier not found", 1);
        }
        if (dirname($fileName) !== $folder) {
            throw new \Exception("Metadata file $identifier is outside the configured metadata folder", 1);
        }
        if (!is_file($fileName)) {
            throw new \Exception("Metadata file $identifier is not a regular file", 1);
        }
        if (!is_readable($fileName)) {
            throw new \Exception("Metadata file $identifier is not readable. Please check file permissions.", 1);
        }
        return $fileName;
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
        // Remember what was actually asked for: without it the response validation
        // has nothing to compare the level the Identity Provider returns against.
        $_SESSION['requestedLevel'] = $level;
        $_SESSION['requestedComparison'] = $this->sp->settings['sp_comparison'] ?? 'exact';

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
        // unset($_SESSION) only dropped this function's own reference to the
        // superglobal, leaving the authenticated session intact after an Identity
        // Provider initiated logout.
        $_SESSION = array();
        session_unset();

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
