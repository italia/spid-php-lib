<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\RequestInterface;
use Italia\Spid\Spid\Saml\Settings;
use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\In\LogoutRequest;
use Italia\Spid\Spid\Saml\SignatureUtils;

class LogoutResponse extends Base implements RequestInterface
{
    public function generateXml()
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $inResponseTo = $_SESSION['inResponseTo'];
        $spEntityId = $this->idp->sp->settings['sp_entityid'];

        $xml = <<<XML
<samlp:LogoutResponse Destination="https://sp.example.com/slo"
    ID="$id" InResponseTo="$inResponseTo"
    IssueInstant="$issueInstant" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="something"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">$spEntityId</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:LogoutResponse>
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
