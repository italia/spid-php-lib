<?php

namespace Italia\Spid\Spid\Saml\Out;

class LogoutRequest extends Base
{
    public function generateXml()
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $entityId = $this->idp->sp->settings['sp_entityid'];
        $idpEntityId = $this->idp->metadata['idpEntityId'];
        $idpSLO = $this->idp->metadata['idpSLO'];
        $index = $this->idp->session->sessionID;
        $xml = <<<XML
<LogoutRequest ID="$id" IssueInstant="$issueInstant" Version="2.0" Destination="$idpSLO">
    <Issuer NameQualifier="$entityId" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">$entityId</Issuer>
    <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="$idpEntityId" />
    <SessionIndex>$index</SessionIndex>
</LogoutRequest>
XML;
        $this->xml = $xml;
    }

    public function redirectUrl($redirectTo = null)
    {
        if (is_null($this->xml)) {
            $this->generateXml();
        }
        $url = $this->idp->metadata['idpSLO'];
        return parent::redirect($url, $redirectTo);
    }
}
