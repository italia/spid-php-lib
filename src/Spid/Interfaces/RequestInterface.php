<?php

namespace Italia\Spid\Spid\Interfaces;

interface RequestInterface
{
    public function generateXml();

    // prepare HTTP-Redirect binding and return it as a string
    // https://github.com/italia/spid-perl/blob/master/lib/Net/SPID/SAML/Out/AuthnRequest.pm#L61
    public function redirectUrl($redirectTo = null) : string;

    // prepare HTTP-POST binding and return the html form as a string
    public function httpPost($redirectTo = null) : string;
}
