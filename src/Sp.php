<?php

namespace Italia\Spid;

use Exception;
use Italia\Spid\Spid\Interfaces\LoggerSelector;

/**
 * @mixin Spid\Saml
 */
class Sp
{
    /*
    * Strategy pattern: initialize the requested protocol based on name provided.
    * Currently only SAML solution is implemented

    * Method calls on Sp call the equivalent method in the chosen strategy implementation
    * Please check SAMLInterface for available methods for SAML Strategy
    */
    private $protocol;

    /**
     * @throws Exception
     */
    public function __construct(LoggerSelector $logger, array $settings, string $protocol = null, $autoconfigure = true)
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        switch ($protocol) {
            case 'saml':
                $this->protocol = new Spid\Saml($logger, $settings, $autoconfigure);
                break;
            default:
                $this->protocol = new Spid\Saml($logger, $settings, $autoconfigure);
        }
    }

    /**
     * @throws Exception
     */
    public function __call($method, $arguments)
    {
        $methods_implemented = get_class_methods($this->protocol);
        if (!in_array($method, $methods_implemented)) {
            throw new Exception("Invalid method [$method] requested", 1);
        }
        return call_user_func_array(array($this->protocol, $method), $arguments);
    }
}
