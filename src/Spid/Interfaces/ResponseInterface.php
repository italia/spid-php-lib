<?php

namespace Italia\Spid\Spid\Interfaces;

interface ResponseInterface
{
    public function validate($xml) : bool;
}
