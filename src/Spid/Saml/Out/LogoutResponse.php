<?php

namespace Italia\Spid\Spid\Saml\Out;

use Italia\Spid\Spid\Interfaces\RequestInterface;
use Italia\Spid\Spid\Saml\Settings;

class LogoutResponse extends Base implements RequestInterface
{
    public function generateXml()
    {
    }

    public function redirectUrl($redirectTo = null) : string
    {
    }

    public function httpPost($redirectTo = null) : string
    {
    }
}
