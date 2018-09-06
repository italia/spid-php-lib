<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\RequestInterface;

class AuthnRequest extends Base implements RequestInterface
{
    public function generateXml()
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $idpUrl = $this->idp->metadata['idpSSO'];
        $entityId = $this->idp->sp->settings['sp_entityid'];

        $assertID = $this->idp->assertID;
        $attrID = $this->idp->attrID;
        $level = $this->idp->level;
        $force = $level > 1 ? "true" : "false";
        
        $authnRequestXml = <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$id" 
    Version="2.0"
    IssueInstant="$issueInstant"
    Destination="$idpUrl"
    ForceAuthn="$force"
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
    }

    public function redirectUrl($redirectTo = null) : string
    {
        if (is_null($this->xml)) {
            $this->generateXml();
        }
        $url = $this->idp->metadata['idpSSO'];
        return parent::redirect($url, $redirectTo);
    }

    public function httpPost()
    {

    }
}
