<?php

declare(strict_types=1);

namespace Italia\Spid\Spid\Interfaces;

use Italia\Spid\Spid\Session;

interface IdpInterface
{
    // Loads an IDP metadata from its XML file
    // $xmlFile: only the name of the file.
    // The path is provided during Sp initialization via settings with the field 'idp_metadata_folder'
    public function loadFromXml($xmlFile);

    // generate an AuthnRequest
    // https://github.com/italia/spid-perl/blob/master/lib/Net/SPID/SAML/IdP.pm#L65
    // $ass: index of assertion consumer service as per the SP metadata
    // $attr: index of attribute consuming service as per the SP metadata
    // $level: SPID level (1, 2 or 3)
    // $returnTo: return url
    // $shouldRedirect: tells if the function should emit headers and redirect to login URL or return the URL as string
    // returns and empty string if $shouldRedirect = true, the login URL otherwise
    public function authnRequest($ass, $attr, $binding, $level = 1, $redirectTo = null, $shouldRedirect = true): string;

    // generate a LogoutRequest
    // $session: the currently active login session
    // $slo: index of singlelogout service as per the SP metadata
    // $binding: HTTP Redirect or HTTP POST binding
    // $returnTo: return url
    // $shouldRedirect: tells if the function should emit headers and redirect to login URL or return the URL as string
    // returns and empty string if $shouldRedirect = true, the logout URL otherwise
    public function logoutRequest(Session $session, $slo, $binding, $redirectTo = null, $shouldRedirect = true): string;

    //generates a logoutResponse in response to an Idp initiated logout request
    public function logoutResponse(): string;
}
