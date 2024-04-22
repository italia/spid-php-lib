<?php

namespace Italia\Spid\Spid;

    use DOMDocument;
    use Exception;
    use InvalidArgumentException;
    use Italia\Spid\Spid\Exceptions\SpidException;
    use Italia\Spid\Spid\Interfaces\LoggerSelector;
    use Italia\Spid\Spid\Interfaces\SAMLInterface;
    use Italia\Spid\Spid\Logging\AbstractLoggerSelector;
    use Italia\Spid\Spid\Saml\Idp;
    use Italia\Spid\Spid\Saml\In\BaseResponse;
    use Italia\Spid\Spid\Saml\Settings;
    use Italia\Spid\Spid\Saml\SignatureUtils;
    use Psr\Log\LogLevel;

class Saml implements SAMLInterface
{
    public $settings;
    private $idps = []; // contains filename -> Idp object array
    private $session; // Session object
    /**
     * @var LoggerSelector
     */
    private $logger;

    /**
     * @throws Exception
     */
    public function __construct(LoggerSelector $logger, array $settings, $autoconfigure = true)
    {
        Settings::validateSettings($settings);
        $this->settings = $settings;
        $this->logger = $logger;

        // Do not attempt autoconfiguration if key and cert values have not been set
        if (!array_key_exists('sp_key_cert_values', $this->settings)) {
            $autoconfigure = false;
        }
        if ($autoconfigure && !$this->isConfigured()) {
            $this->configure();
        }
    }

    /**
     * @throws Exception
     */
    public function loadIdpFromFile(string $filename)
    {
        if (empty($filename)) {
            return null;
        }
        if (array_key_exists($filename, $this->idps)) {
            return $this->idps[$filename];
        }
        $idp = new Idp($this);
        $this->idps[$filename] = $idp->loadFromXml($filename);
        return $idp;
    }

    /**
     * @throws Exception
     */
    public function getIdpList(): array
    {
        $files = glob($this->settings['idp_metadata_folder'] . "*.xml");

        if (is_array($files)) {
            $mapping = [];
            foreach ($files as $filename) {
                $idp = $this->loadIdpFromFile($filename);
                $mapping[basename($filename, ".xml")] = $idp->metadata['idpEntityId'];
            }
            return $mapping;
        }
        return [];
    }

    /**
     * @throws Exception
     */
    public function getIdp(string $filename)
    {
        return $this->loadIdpFromFile($filename);
    }

    /**
     * @throws Exception
     */
    public function getSPMetadata(): string
    {
        if (!is_readable($this->settings['sp_cert_file'])) {
            return <<<XML
            <error>Your SP certificate file is not readable. Please check file permissions.</error>
XML;
        }

        $entityID = htmlspecialchars($this->settings['sp_entityid'], ENT_XML1);
        $id = preg_replace('/[^a-z0-9_-]/', '_', $entityID);
        $cert = Settings::cleanOpenSsl($this->settings['sp_cert_file']);

        $sloLocationArray = $this->settings['sp_singlelogoutservice'] ?? [];
        $assertcsArray = $this->settings['sp_assertionconsumerservice'] ?? [];
        $attrcsArray = $this->settings['sp_attributeconsumingservice'] ?? [];

        $xml = <<<XML
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:spid="https://spid.gov.it/saml-extensions"
                     entityID="$entityID"
                     ID="$id">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                        AuthnRequestsSigned="true"
                        WantAssertionsSigned="true">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data><ds:X509Certificate>$cert</ds:X509Certificate></ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
XML;
        foreach ($sloLocationArray as $slo) {
            $location = htmlspecialchars($slo[0], ENT_XML1);
            $binding = $slo[1];
            if (strcasecmp($binding, "POST") === 0 || strcasecmp($binding, "") === 0) {
                $binding = Settings::BINDING_POST;
            } else {
                $binding = Settings::BINDING_REDIRECT;
            }
            $xml .= <<<XML

            <md:SingleLogoutService Binding="$binding" Location="$location"/>
XML;
        }
        $xml .= <<<XML
        
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
XML;
        for ($i = 0; $i < count($assertcsArray); $i++) {
            $location = htmlspecialchars($assertcsArray[$i], ENT_XML1);
            $xml .= <<<XML

        <md:AssertionConsumerService index="$i"
                                     isDefault="true"
                                     Location="$location"
                                     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
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

        if (array_key_exists('sp_contact_aggregator_person_type', $this->settings)) {
            $aggregatorContactCompany = $this->settings['sp_contact_aggregator_company'];
            $aggregatorContactPersonType = $this->settings['sp_contact_aggregator_person_type'];
            $aggregatorContactPersonVATNumber = $this->settings['sp_contact_aggregator_person_vat_number'];
            $aggregatorContactPersonFiscalCode = $this->settings['sp_contact_aggregator_person_fiscal_code'];
            $aggregatorContactPersonEmail = $this->settings['sp_contact_aggregator_person_email'];
            $aggregatorContactPersonPhone = $this->settings['sp_contact_aggregator_person_phone'];
            $xml .= <<<XML
<md:ContactPerson
        contactType="$aggregatorContactPersonType"
        spid:entityType="spid:aggregator">
     <md:Extensions>
        <spid:VATNumber>$aggregatorContactPersonVATNumber</spid:VATNumber>
        <spid:FiscalCode>$aggregatorContactPersonFiscalCode</spid:FiscalCode>
        <spid:PublicServicesFullAggregator/>
     </md:Extensions>
     <md:Company>$aggregatorContactCompany</md:Company>
     <md:EmailAddress>$aggregatorContactPersonEmail</md:EmailAddress>
     <md:TelephoneNumber>$aggregatorContactPersonPhone</md:TelephoneNumber>
</md:ContactPerson>
XML;
        }

        if (array_key_exists('sp_contact_aggregate_person_type', $this->settings)) {
            $aggregateContactIpaCode = $this->settings['sp_contact_aggregate_ipa_code'];
            $aggregateContactPersonCompany = $this->settings['sp_contact_aggregate_company'];
            $aggregateContactPersonType = $this->settings['sp_contact_aggregate_person_type'];
            $xml .= <<<XML
<md:ContactPerson
        contactType="$aggregateContactPersonType"
        spid:entityType="spid:aggregated">
    <md:Extensions>
        <spid:IPACode>$aggregateContactIpaCode</spid:IPACode>
        <spid:Public/>
    </md:Extensions>
    <md:Company>$aggregateContactPersonCompany</md:Company>
XML;
            if (array_key_exists('sp_contact_aggregate_email', $this->settings)) {
                $aggregateEmail = $this->settings['sp_contact_aggregate_email'];
                $xml .= "<md:EmailAddress>$aggregateEmail</md:EmailAddress>";
            }

            if (array_key_exists('sp_contact_aggregate_telephone', $this->settings)) {
                $aggregateTelephone = $this->settings['sp_contact_aggregate_telephone'];
                $xml .= "<md:TelephoneNumber>$aggregateTelephone</md:TelephoneNumber>";
            }

            $xml .= '</md:ContactPerson>';
        }

        $xml .= '</md:EntityDescriptor>';

        return SignatureUtils::signXml($xml, $this->settings);
    }

    /**
     * @throws Exception
     */
    public function login(
        string $idpName,
        int $assertId,
        int $attrId,
        $level = 1,
        string $redirectTo = null,
        $shouldRedirect = true
    ) {
        $args = func_get_args();
        return $this->baseLogin(Settings::BINDING_REDIRECT, ...$args);
    }

    /**
     * @throws Exception
     */
    public function loginPost(
        string $idpName,
        int $assertId,
        int $attrId,
        $level = 1,
        string $redirectTo = null,
        $shouldRedirect = true
    ) {
        $args = func_get_args();
        return $this->baseLogin(Settings::BINDING_POST, ...$args);
    }

    /**
     * @throws SpidException
     * @throws Exception
     */
    private function baseLogin(
        $binding,
        $idpName,
        $assertId,
        $attrId,
        $level = 1,
        $redirectTo = null,
        $shouldRedirect = true
    ) {
        if ($this->isAuthenticated()) {
            return false;
        }
        if (!array_key_exists($assertId, $this->settings['sp_assertionconsumerservice'])) {
            throw new Exception("Invalid Assertion Consumer Service ID");
        }
        if (isset($this->settings['sp_attributeconsumingservice'])) {
            if (!isset($this->settings['sp_attributeconsumingservice'][$attrId])) {
                throw new Exception("Invalid Attribute Consuming Service ID");
            }
        } else {
            $attrId = null;
        }

        $idp = $this->loadIdpFromFile($idpName);
        return $idp->authnRequest($assertId, $attrId, $binding, $level, $redirectTo, $shouldRedirect);
    }

    /**
     * @throws SpidException
     * @throws Exception
     */
    public function isAuthenticated(): bool
    {
        $selectedIdp = $_SESSION['idpName'] ?? $_SESSION['spidSession']['idp'] ?? null;
        if (is_null($selectedIdp)) {
            $this->logAuthenticationErrors("session error");
            return false;
        }
        $idp = $this->loadIdpFromFile($selectedIdp);
        $response = new BaseResponse($this);
        if (!empty($idp) && !$response->validate($idp->metadata['idpCertValue'])) {
            $this->logAuthenticationErrors("invalid metadata");
            return false;
        }
        if (isset($_SESSION['inResponseTo'])) {
            $idp->logoutResponse();
            $this->logAuthenticationErrors("isset inResponseTo");
            return false;
        }
        if (isset($_SESSION['spidSession'])) {
            $session = new Session($_SESSION['spidSession']);
            if ($session->isValid()) {
                $this->session = $session;
                return true;
            }
        }

        $this->logAuthenticationErrors("unknown case");
        return false;
    }

    /**
     * @throws SpidException
     */
    public function logout(int $slo, string $redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogout(Settings::BINDING_REDIRECT, ...$args);
    }

    /**
     * @throws SpidException
     */
    public function logoutPost(int $slo, string $redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogout(Settings::BINDING_POST, ...$args);
    }

    /**
     * @throws SpidException
     * @throws Exception
     */
    private function baseLogout($binding, $slo, $redirectTo = null, $shouldRedirect = true)
    {
        if (!$this->isAuthenticated()) {
            return false;
        }
        $idp = $this->loadIdpFromFile($this->session->idp);
        return $idp->logoutRequest($this->session, $slo, $binding, $redirectTo, $shouldRedirect);
    }

    /**
     * @throws SpidException
     */
    public function getAttributes(): array
    {
        if ($this->isAuthenticated() === false) {
            return [];
        }
        return isset($this->session->attributes) && is_array($this->session->attributes)
            ? $this->session->attributes
            : [];
    }

    // returns true if the SP certificates are found where the settings says they are, and they are valid
    // (i.e. the library has been configured correctly
    private function isConfigured(): bool
    {
        if (!is_readable($this->settings['sp_key_file'])) {
            return false;
        }
        if (!is_readable($this->settings['sp_cert_file'])) {
            return false;
        }
        $key = file_get_contents($this->settings['sp_key_file']);
        if (!openssl_get_privatekey($key)) {
            return false;
        }
        $cert = file_get_contents($this->settings['sp_cert_file']);
        if (!openssl_get_publickey($cert)) {
            return false;
        }
        if (!SignatureUtils::certDNEquals($cert, $this->settings)) {
            return false;
        }
        return true;
    }

    // Generates with openssl the SP certificates where the settings says they should be
    // this function should be used with care because it requires write access to the filesystem,
    // and invalidates the metadata
    private function configure()
    {
        $keyCert = SignatureUtils::generateKeyCert($this->settings);
        $dir = dirname($this->settings['sp_key_file']);
        if (!is_dir($dir)) {
            throw new InvalidArgumentException(
                "The directory you selected for sp_key_file does not exist. Please create $dir"
            );
        }
        $dir = dirname($this->settings['sp_cert_file']);
        if (!is_dir($dir)) {
            throw new InvalidArgumentException(
                "The directory you selected for sp_cert_file does not exist. Please create $dir"
            );
        }
        file_put_contents($this->settings['sp_key_file'], $keyCert['key']);
        file_put_contents($this->settings['sp_cert_file'], $keyCert['cert']);
    }

    private function logAuthenticationErrors(string $errorMessage): void
    {
        $xml = null;
        if (isset($_GET['SAMLResponse'])) {
            $xml = gzinflate(base64_decode($_GET['SAMLResponse']));
        } elseif (isset($_POST['SAMLResponse'])) {
            $xml = base64_decode($_POST['SAMLResponse']);
        }

        $errorLevel = LogLevel::ERROR;
        $additionalErrorInfo = '';

        if ($xml) {
            $dom = new DOMDocument();
            $dom->loadXML($xml);
            $statusMessageElement = $dom->getElementsByTagName('StatusMessage');
            if ($statusMessageElement->item(0)->nodeValue) {
                $errorString = $statusMessageElement->item(0)->nodeValue;
                $errorCode = intval(str_replace('ErrorCode nr', '', $errorString));
                $errorLevel = AbstractLoggerSelector::getErrorLevel($errorCode);
                $additionalErrorInfo = ' ' . AbstractLoggerSelector::getErrorMessage($errorCode) ;
            }
        }

        if ($this->logger->getTemporaryLogger()) {
            $this->logger->getTemporaryLogger()->log(
                $errorLevel,
                "Saml::isAuthenticated error{$additionalErrorInfo}: {$errorMessage}"
                . PHP_EOL
                . "SESSION: " . var_export($_SESSION, true)
            );
        }
        if ($this->logger->getPermanentLogger()) {
            $this->logger->getPermanentLogger()->log(
                $errorLevel,
                "Saml::isAuthenticated error{$additionalErrorInfo}",
                ['xml' => $xml, 'error_message' => $additionalErrorInfo]
            );
        }
    }

    public function getLogger(): LoggerSelector
    {
        return $this->logger;
    }
}
