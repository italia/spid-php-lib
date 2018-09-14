<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\RequestInterface;
use Italia\Spid\Spid\Saml\Settings;
use Italia\Spid\Spid\Saml\SignatureUtils;

class LogoutRequest extends Base implements RequestInterface
{
    public function generateXml()
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $entityId = $this->idp->sp->settings['sp_entityid'];
        $idpEntityId = $this->idp->metadata['idpEntityId'];
        $index = $this->idp->session->sessionID;
        $xml = <<<XML
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
ID="$id" IssueInstant="$issueInstant" Version="2.0" Destination="$idpEntityId">
    <saml:Issuer NameQualifier="$entityId" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">$entityId</saml:Issuer>
    <saml:NameID NameQualifier="$idpEntityId" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">$idpEntityId</saml:NameID>
    <samlp:SessionIndex>$index</samlp:SessionIndex>
</samlp:LogoutRequest>
XML;
        $this->xml = $xml;
    }

    public function redirectUrl($redirectTo = null) : string
    {
        $location = parent::getBindingLocation(Settings::BINDING_POST, 'SLO');
        if (is_null($this->xml)) {
            $this->generateXml();
        }
        return parent::redirect($location, $redirectTo);
    }

    public function httpPost($redirectTo = null) : string
    {
        $location = parent::getBindingLocation(Settings::BINDING_POST, 'SLO');
        if (is_null($this->xml)) {
            $this->generateXml();
        }
        
        $this->xml = SignatureUtils::signXml($this->xml, $this->idp->sp->settings);
        return parent::postForm($location, $redirectTo);
    }
}
