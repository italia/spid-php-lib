<?php
declare(strict_types=1);

require_once(__DIR__ . "/../vendor/autoload.php");

final class ValidTest extends PHPUnit\Framework\TestCase
{
    private static $settings = [
        'sp_entityid' => 'http://sp3.simevo.com/',
        'sp_key_file' => './example/test_sp.key',
        'sp_cert_file' => './example/test_sp.crt',
        'sp_assertionconsumerservice' => ['http://sp3.simevo.com/acs'],
        'sp_singlelogoutservice' => [
            ['http://sp3.simevo.com/slo', ''],
            ['http://sp3.simevo.com/slo', 'REDIRECT']
        ],
        'sp_org_name' => 'test_simevo',
        'sp_org_display_name' => 'Test Simevo',
        'sp_key_cert_values' => [
            'countryName' => 'IT',
            'stateOrProvinceName' => 'Milan',
            'localityName' => 'Milan',
            'commonName' => 'Name',
            'emailAddress' => 'test@test.com',
        ],
        'idp_metadata_folder' => './example/idp_metadata/',
        'sp_attributeconsumingservice' => [
            ["name", "familyName", "fiscalNumber", "email"],
            ["name", "familyName", "fiscalNumber", "email", "spidCode"]
            ]
        ];

    public function testValidateResponse()
    {
        $saml = new Italia\Spid\Spid\Saml(ValidTest::$settings);

        // mock session data
        $_SESSION['RequestID'] = "_4d38c302617b5bf98951e65b4cf304711e2166df20";
        $_SESSION['acsUrl'] = "http://spid-sp.it";
        $_SESSION['idpEntityId'] = "spididp.it";
        $_SESSION['idpName'] = "";

        $text = <<<XML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
    ID="_66bc42b27638a8641536e534ec09727a8aaa" 
    Version="2.0" 
    InResponseTo="_4d38c302617b5bf98951e65b4cf304711e2166df20" 
    IssueInstant="2015-01-29T10:01:03Z" 
    Destination="http://spid-sp.it">
  <saml:Issuer NameQualifier="https://spidIdp.spidIdpProvider.it"
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">spididp.it</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    ............. 
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /> 
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
      ID="_27e00421b56a5aa5b73329240ce3bb832caa" 
      IssueInstant="2015-01-29T10:01:03Z" Version="2.0">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">WrongIssuer</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      ......
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" 
          NameQualifier="http://spidIdp.spididpProvider.it">
        _06e983facd7cd554cfe067e 
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://spidSP.serviceProvider.it/" 
        NotOnOrAfter="2001-12-31T12:00:00" 
        InResponseTo="_4d38c302617b5bf98951e65b4cf304711e2166df20">
        </saml:SubjectConfirmationData>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2015-01-29T10:00:33Z" 
        NotOnOrAfter="2015-01-29T10:02:33Z">
      <saml:AudienceRestriction>
        <saml:Audience>
          https://spidSP.serviceProvider.it 
        </saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2015-01-29T10:01:02Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          https://www.spid.gov.it/SpidL1
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement xmlns:xsi="http://www.w3.org/2001/XMLSchemainstance">
      <saml:Attribute Name="familyName">
        <saml:AttributeValue xsi:type="xsi:string">
          Rossi
        </saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="spidCode">
        <saml:AttributeValue xsi:type="xsi:string">
          ABCDEFGHILMNOPQ 
        </saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML;
        $xml = new \DOMDocument();
        $xml->loadXML($text);
        $response = new Italia\Spid\Spid\Saml\In\Response($saml);
        $this->assertTrue($response->validate($xml, false));
    }
}
