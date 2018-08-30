<?php

namespace Italia\Spid\Spid\Interfaces;

use Italia\Spid\Spid\Session;

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
    // $shouldRedirect: tells if the function should emit headers and redirect to login URL or return the URL as string
    // returns and empty string if $shouldRedirect = true, the login URL otherwhise
    public function authnRequest($ass, $attr, $level, $returnTo = null, $shouldRedirect = true) : string;

    // generate a LogoutRequest
    // $session: the currently active login session
    // $returnTo: return url
    // $shouldRedirect: tells if the function should emit headers and redirect to login URL or return the URL as string
    // returns and empty string if $shouldRedirect = true, the logout URL otherwhise
    public function logoutRequest(Session $session, $returnTo = null, $shouldRedirect = true) : string;
}
