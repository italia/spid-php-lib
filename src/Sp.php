<?php

namespace Italia\Spid;

class Sp
{
    private $protocol;

    public function __construct(array $settings, String $protocol = null)
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        switch ($protocol) {
            case 'saml':
                $this->protocol = new Spid\Saml($settings);
                break;
            default:
                $this->protocol = new Spid\Saml($settings);
        }
    }

    public function __call($method, $arguments)
    {
        $methods_implemented = get_class_methods($this->protocol);
        if (!in_array($method, $methods_implemented)) {
            throw new \Exception("Invalid method requested", 1);
        }
        return call_user_func_array(array($this->protocol, $method), $arguments);
    }
}
