<?xml version="1.0"?>
<md:EntityDescriptor 
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"  
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"  
    entityID="${SP_SCHEMA}://${SP_FQDN}:${SP_PORT}"
    ID="_fbec471-cc7d-4eb4-a1b1-216df7c0f4ab"> 
     
    <md:SPSSODescriptor  
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"  
        AuthnRequestsSigned="true"  
        WantAssertionsSigned="true"> 
        
        <md:KeyDescriptor use="signing"> 
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
                <ds:X509Data> 
                    <ds:X509Certificate>${SP_CRT}</ds:X509Certificate> 
                </ds:X509Data> 
            </ds:KeyInfo> 
        </md:KeyDescriptor> 
        
        <md:KeyDescriptor use="encryption"> 
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
                <ds:X509Data> 
                    <ds:X509Certificate>${SP_CRT}</ds:X509Certificate> 
                </ds:X509Data> 
            </ds:KeyInfo> 
        </md:KeyDescriptor> 
        
        <md:SingleLogoutService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="${SP_SCHEMA}://${SP_FQDN}:${SP_PORT}/logout" />

        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat> 

        <md:AssertionConsumerService  
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"  
            Location="${SP_SCHEMA}://${SP_FQDN}:${SP_PORT}/acs"
            index="0"  
            isDefault="true" /> 

        <md:AttributeConsumingService index="1"> 
            <md:ServiceName xml:lang="it">${SP_NAME}</md:ServiceName> 
            <md:ServiceDescription xml:lang="it">${SP_NAME}</md:ServiceDescription> 
            <md:RequestedAttribute Name="spidCode" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="gender" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="placeOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="ivaCode" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="companyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="fiscalNumber" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="familyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="dateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="countyOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="idCard" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="registeredOffice" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="digitalAddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="mobilePhone" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="address" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            <md:RequestedAttribute Name="expirationDate" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
        </md:AttributeConsumingService> 

    </md:SPSSODescriptor> 

</md:EntityDescriptor>
 
