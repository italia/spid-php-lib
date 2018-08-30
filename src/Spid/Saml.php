<?php

namespace Italia\Spid\Spid;

use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\In\Base;
use Italia\Spid\Spid\Saml\In\Response;
use Italia\Spid\Spid\Saml\Settings;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Saml implements Interfaces\SpInterface
{
    var $settings;
    var $idps = [];
    var $session;

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

    public function getSPMetadata() : string
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

        $key = file_get_contents($this->settings['sp_key_file']);
        $key = openssl_get_privatekey($key, "");
        $cert = file_get_contents($this->settings['sp_cert_file']);
        $signAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        $digestAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256';
        $dom = new \DOMDocument();
        $dom->loadXML($xml);
        if (!$dom) {
            throw new Exception('Error parsing xml string');
        }
        $objKey = new XMLSecurityKey($signAlgorithm, array('type' => 'private'));
        $objKey->loadKey($key, false);
        $rootNode = $dom->firstChild;
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objXMLSecDSig->addReferenceList(
            array($rootNode),
            $digestAlgorithm,
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            array('id_name' => 'ID')
        );
        $objXMLSecDSig->sign($objKey);
        $objXMLSecDSig->add509Cert($cert, true);
        $insertBefore = $rootNode->firstChild;
        $messageTypes = array('AuthnRequest', 'Response', 'LogoutRequest','LogoutResponse');
        if (in_array($rootNode->localName, $messageTypes)) {
            $issuerNodes = self::query($dom, '/'.$rootNode->tagName.'/saml:Issuer');
            if ($issuerNodes->length == 1) {
                $insertBefore = $issuerNodes->item(0)->nextSibling;
            }
        }
        $objXMLSecDSig->insertSignature($rootNode, $insertBefore);
        $signedxml = $dom->saveXML();
        return $signedxml;
    }

    public function getIdp($idpName)
    {
        return key_exists($idpName, $this->idps) ? $this->idps[$idpName] : false;
    }

    public function login($idpName, $assertId, $attrId, $redirectTo = null, $level = 1)
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
        $idp->authnRequest($assertId, $attrId, $redirectTo, $level);
    }

    public function isAuthenticated()
    {
        if (isset($_SESSION) && isset($_SESSION['spidSession'])) {
            $this->session = $_SESSION['spidSession'];
            return true;
        }

        $response = new Response();
        $validated = $response->validate();
        if ($validated instanceof Session) {
            $_SESSION['spidSession'] = $validated;
            $this->session = $validated;
            return true;
        }
        return false;
    }

    public function logout($redirectTo = null)
    {
        if ($this->isAuthenticated() === false) {
            return false;
        }
        $this->loadIdpFromFile($this->session->idp);
        $idp = $this->idps[$this->session->idp];
        $idp->logoutRequest($this->session, $redirectTo);
    }

    public function getAttributes()
    {
        return $this->session->attributes;
    }

    public function loadIdpMetadata($path)
    {
        // TODO: Implement loadIdpMetadata() method.
    }
}
