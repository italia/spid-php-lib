<?php

namespace Italia\Spid\Spid\Saml\In;

use Italia\Spid\Spid\Interfaces\ResponseInterface;

class LogoutRequest implements ResponseInterface
{
    public function validate($xml) : bool
    {
        
    }
}