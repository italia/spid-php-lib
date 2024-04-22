<?php

namespace Italia\Spid\Spid\Saml\Out;

use Exception;
use Italia\Spid\Spid\Interfaces\LoggerSelector;
use Italia\Spid\Spid\Interfaces\RequestInterface;
use Italia\Spid\Spid\Saml\Idp;
use Italia\Spid\Spid\Saml\Settings;
use Italia\Spid\Spid\Saml\SignatureUtils;
use SimpleXMLElement;

class AuthnRequest extends Base implements RequestInterface
{
    private $logger;

    public function __construct(Idp $idp, LoggerSelector $logger)
    {
        parent::__construct($idp);
        $this->logger = $logger;
    }

    /**
     * @throws Exception
     */
    public function generateXml()
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $entityId = $this->idp->sp->settings['sp_entityid'];

        $idpEntityId = $this->idp->metadata['idpEntityId'];
        $assertID = $this->idp->assertID;
        $attrID = $this->idp->attrID;
        $level = $this->idp->level;
        $comparison = $this->idp->sp->settings['sp_comparison'] ?? "exact";
        $force = ($level > 1 || $comparison == "minimum") ? "true" : "false";

        $authnRequestXml = <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$id" 
    Version="2.0"
    IssueInstant="$issueInstant"
    Destination="$idpEntityId"
    ForceAuthn="$force"
    AssertionConsumerServiceIndex="$assertID">
    <saml:Issuer
        NameQualifier="$entityId"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">$entityId</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <samlp:RequestedAuthnContext Comparison="$comparison">
        <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL$level</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
XML;

        $xml = new SimpleXMLElement($authnRequestXml);

        if (!is_null($attrID)) {
            $xml->addAttribute('AttributeConsumingServiceIndex', $attrID);
        }
        $this->xml = $xml->asXML();
        $logger = $this->logger->getPermanentLogger();
        if ($logger) {
            $logger->info('AuthnRequest', [
                'xml' => $this->xml,
                'schema' => 'AuthnRequest'
            ]);
        }
    }

    /**
     * @throws Exception
     */
    public function redirectUrl($redirectTo = null): string
    {
        $location = parent::getBindingLocation(Settings::BINDING_REDIRECT);
        if (is_null($this->xml)) {
            $this->generateXml();
        }
        return parent::redirect($location, $redirectTo);
    }

    /**
     * @throws Exception
     */
    public function httpPost($redirectTo = null): string
    {
        $location = parent::getBindingLocation(Settings::BINDING_POST);
        if (is_null($this->xml)) {
            $this->generateXml();
        }
        $this->xml = SignatureUtils::signXml($this->xml, $this->idp->sp->settings);
        return parent::postForm($location, $redirectTo);
    }
}
