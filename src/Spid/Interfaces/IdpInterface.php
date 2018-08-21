<?php

namespace Italia\Spid\Spid\Interfaces;

interface IdpInterface
{
    // Loads an IDP metadata from its XML file
    // $xmlFile: file path relative from the project root
    public function loadFromXml($xmlFile);

    // generate an AuthnRequest
    // https://github.com/italia/spid-perl/blob/master/lib/Net/SPID/SAML/IdP.pm#L65
    // $ass: index of assertion consumer service as per the SP metadata
    // $attr: index of attribute consuming service as per the SP metadata
    // $level: SPID level (1, 2 or 3)
    // $returnTo: return url
    public function authnRequest($ass, $attr, $level, $returnTo);
}
