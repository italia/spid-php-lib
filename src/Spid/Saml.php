<?php

namespace Italia\Spid\Spid;

use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\In\BaseResponse;
use Italia\Spid\Spid\Saml\Settings;
use Italia\Spid\Spid\Saml\SignatureUtils;

class Saml implements Interfaces\SAMLInterface
{
    var $settings;
    var $idps = []; // contains filename -> Idp object array
    var $session; // Session object

    public function __construct(array $settings)
    {
        Settings::validateSettings($settings);
        $this->settings = $settings;
    }

    public function loadIdpFromFile($filename)
    {
        if (empty($filename)) return null;
        if (array_key_exists($filename, $this->idps)) {
            return $this->idps[$filename];
        }
        $idp = new Idp($this);
        $this->idps[$filename] = $idp->loadFromXml($filename);
        return $idp;
    }

    public function getIdpList() : array
    {
        $files = glob($this->settings['idp_metadata_folder'] . "/*xml");

        if (is_array($files)) {
            $mapping = array();
            foreach($files as $filename) {
                $idp = $this->loadIdpFromFile($filename);
                $mapping[$idp->metadata['idpEntityId']] = $filename;
            }
            return $mapping;
        }
        return array();
    }

    public function getIdp($filename)
    {
        return $this->loadIdpFromFile($filename);
    }

    public function getSPMetadata(): string
    {
        $entityID = $this->settings['sp_entityid'];
        $id = preg_replace('/[^a-z0-9_-]/', '_', $entityID);
        $cert = Settings::cleanOpenSsl($this->settings['sp_cert_file']);

        $sloLocation = $this->settings['sp_singlelogoutservice'];
        $assertcsArray = $this->settings['sp_assertionconsumerservice'] ?? array();
        $attrcsArray = $this->settings['sp_attributeconsumingservice'] ?? array();

        $xml = <<<XML
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="$entityID" ID="$id">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data><ds:X509Certificate>$cert</ds:X509Certificate></ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="$sloLocation"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
XML;
        for ($i = 0; $i < count($assertcsArray); $i++) {
            $xml .= <<<XML

        <md:AssertionConsumerService index="$i" isDefault="true" Location="$assertcsArray[$i]" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
XML;
        }
        for ($i = 0; $i < count($attrcsArray); $i++) {
            $xml .= <<<XML

        <md:AttributeConsumingService index="$i">
            <md:ServiceName xml:lang="it">Set $i</md:ServiceName>       
XML;
            foreach ($attrcsArray[$i] as $attr) {
                $xml .= <<<XML

            <md:RequestedAttribute Name="$attr"/>
XML;
            }
            $xml .= '</md:AttributeConsumingService>';
        }
        $xml .= '</md:SPSSODescriptor>';


        if (array_key_exists('sp_org_name', $this->settings)) {
            $orgName = $this->settings['sp_org_name'];
            $orgDisplayName = $this->settings['sp_org_display_name'];
            $xml .= <<<XML
<md:Organization>
    <md:OrganizationName xml:lang="it">$orgName</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="it">$orgDisplayName</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="it">$entityID</md:OrganizationURL>
</md:Organization>
XML;
        }
        $xml .= '</md:EntityDescriptor>';

        return SignatureUtils::signXml($xml, $this->settings);
    }

    public function login($idpName, $assertId, $attrId, $level = 1, $redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogin(Settings::BINDING_REDIRECT, ...$args);
    }

    public function loginPost($idpName, $assertId, $attrId, $level = 1, $redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogin(Settings::BINDING_POST, ...$args);
    }

    private function baseLogin($binding = Settings::BINDING_REDIRECT, $idpName, $assertId, $attrId, $level = 1, $redirectTo = null, $shouldRedirect = true)
    {
        if ($this->isAuthenticated()) {
            return false;
        }
        if (!array_key_exists($assertId, $this->settings['sp_assertionconsumerservice'])) {
            throw new \Exception("Invalid Assertion Consumer Service ID");
        }
        if (isset($this->settings['sp_attributeconsumingservice'])) {
            if (!isset($this->settings['sp_attributeconsumingservice'][$attrId])) {
                throw new \Exception("Invalid Attribute Consuming Service ID");
            }
        } else {
            $attrId = null;
        }

        $idp = $this->loadIdpFromFile($idpName);
        return $idp->authnRequest($assertId, $attrId, $binding, $level, $redirectTo, $shouldRedirect);
    }

    public function isAuthenticated() : bool
    {
        $idp = $this->loadIdpFromFile($_SESSION['idpName'] ?? $_SESSION['spidSession']->idp);
        $response = new BaseResponse();
        if (!empty($idp) && !$response->validate($idp->metadata['idpCertValue'])) {
            return false;
        }
        if (isset($_SESSION) && isset($_SESSION['inResponseTo'])) {
            $idp->logoutResponse();
            return false;
        }
        if (isset($_SESSION) && isset($_SESSION['spidSession'])) {
            $this->session = $_SESSION['spidSession'];
            return true;
        }
        return false;
    }

    public function logout($redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogout(Settings::BINDING_REDIRECT, ...$args);
    }

    public function logoutPost($redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogout(Settings::BINDING_POST, ...$args);
    }

    private function baseLogout($binding = Settings::BINDING_REDIRECT, $redirectTo = null, $shouldRedirect = true)
    {
        if (!$this->isAuthenticated()) {
            return false;
        }
        $idp = $this->loadIdpFromFile($this->session->idp);
        return $idp->logoutRequest($this->session, $binding, $redirectTo, $shouldRedirect);
    }

    public function getAttributes() : array
    {
        return $this->session->attributes;
    }
}
