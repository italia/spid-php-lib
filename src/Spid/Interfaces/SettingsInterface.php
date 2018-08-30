<?php

namespace Italia\Spid\Spid\Interfaces;

interface SettingsInterface
{
    public function __construct($entityID, $spKeyFile, $spCertFile, $spAssertionConsumerService, $spSLO, $spAttributeConsumingService = null);

    public function getEntityID();

    public function getSpKeyFile();

    public function getSpCertFile();

    public function getSpAssertionConsumerService();

    public function getSpSLO();

    public function getSpAttributeConsumingService();
}