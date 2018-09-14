<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\RequestInterface;
use Italia\Spid\Spid\Saml\Settings;
use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\In\LogoutRequest;

class LogoutResponse extends Base implements RequestInterface
{
    private $logoutRequest;

    public function __construct(Idp $idp, LogoutRequest $logoutRequest)
    {
        parent::__construct($idp);
        $this->logoutRequest = $logoutRequest;
    }
    public function generateXml()
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();

        $xml = <<<XML
<samlp:LogoutResponse Destination="https://sp.example.com/slo"
    ID="id_c617f55ce9bc9d66000a7be3bea9d118fb2db61f" InResponseTo="_186e2ce13158cde96297c9f5dd9e993a"
    IssueInstant="2018-09-14T08:14:57Z" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="something"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">http://0.0.0.0:8088</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:LogoutResponse>
XML;
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
