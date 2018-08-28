<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\AuthnRequestInterface;

class AuthnRequest extends Base implements AuthnRequestInterface
{
    public function generateXml()
    {
        $id = $this->generateID();
        $signature = $this->buildXmlSignature($id);
        $issueInstant = $this->generateIssueInstant();
        $idpUrl = $this->idp->metadata['idpSSO'];
        $entityId = $this->idp->settings['sp_entityid'];

        $assertID = $this->idp->assertID;
        $attrID = $this->idp->attrID;
        $level = $this->idp->level;
        $force = $level > 1 ? "true" : "false";
        // example ID _4d38c302617b5bf98951e65b4cf304711e2166df20
        $authnRequestXml = <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$id" 
    Version="2.0"
    IssueInstant="$issueInstant"
    Destination="$idpUrl"
    ForceAuthn="$force"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceIndex="$assertID">
    <saml:Issuer
        NameQualifier="$entityId"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">$entityId</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL$level</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
XML;

        $xml = new \SimpleXMLElement($authnRequestXml);

        if (!is_null($attrID)) {
            $xml->addAttribute('AttributeConsumingServiceIndex', $attrID);
        }

        $this->xml = $xml->asXML();

/*        header('Content-type: text/xml');
        echo $this->xml;*/
    }

    public function redirectUrl($redirectTo = null)
    {
        if (is_null($this->xml)) {
            $this->generateXml();
        }
        $url = $this->idp->metadata['idpSSO'];
        return parent::redirectUrl($url, $redirectTo);
    }
}
