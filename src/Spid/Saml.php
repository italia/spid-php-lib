<?php

namespace Italia\Spid\Spid;

use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\In\BaseResponse;
use Italia\Spid\Spid\Saml\In\LogoutResponse;
use Italia\Spid\Spid\Saml\In\Response;
use Italia\Spid\Spid\Saml\Settings;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Italia\Spid\Spid\Saml\SignatureUtils;

class Saml implements Interfaces\SpInterface
{
    var $settings;
    var $idps = [];
    var $session;

    const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
    const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    public function __construct(array $settings)
    {
        Settings::validateSettings($settings);
        $this->settings = $settings;
    }

    public function loadIdpFromFile($filename)
    {
        if (array_key_exists($filename, $this->idps)) {
            return;
        }
        $idp = new Idp($this);
        $this->idps[$filename] = $idp->loadFromXml($filename);;
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

    public function getIdp($idpName) : Idp
    {
        return key_exists($idpName, $this->idps) ? $this->idps[$idpName] : null;
    }

    public function login($idpName, $assertId, $attrId, $level = 1, $redirectTo = null, $shouldRedirect = true)
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

        $this->loadIdpFromFile($idpName);
        $idp = $this->idps[$idpName];
        return $idp->authnRequest($assertId, $attrId, $redirectTo, $level, $shouldRedirect);
    }

    public function isAuthenticated() : bool
    {
        $response = new BaseResponse();
        if (!$response->validate()) {
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
        if (!$this->isAuthenticated()) {
            return false;
        }
        $this->loadIdpFromFile($this->session->idp);
        $idp = $this->idps[$this->session->idp];
        return $idp->logoutRequest($this->session, $redirectTo, $shouldRedirect);
    }

    public function getAttributes() : array
    {
        return $this->session->attributes;
    }

    public function loadIdpMetadata($path)
    {
        // TODO: Implement loadIdpMetadata() method.
    }
}
