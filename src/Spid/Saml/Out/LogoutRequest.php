<?php

namespace Italia\Spid\Spid\Saml\Out;

class LogoutRequest extends Base
{
    public function generateXml()
    {
        $xml = <<<XML
<LogoutRequest ID="" IssueInstant="" Version="2.0" Destination="">
    <Issuer NameQualifier="$entityId" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">$entityId</Issuer>
    <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="$idpEntityId" />
    <SessionIndex>$index</SessionIndex>
</LogoutRequest>
XML;
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
