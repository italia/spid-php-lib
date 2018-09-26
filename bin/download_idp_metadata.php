#!/usr/bin/php
<?php
// downloads the metadata for all current idps from the registry
// and stores them all in the specified directory
//
// prerequisites:
//   sudo apt install php-curl
//
// usage:
//   ./bin/download_idp_metadata.php /tmp/idp_metadata
//
// Copyright (c) 2018, Paolo Greppi <paolo.greppi@simevo.com>
// License: BSD 3-Clause

if (count($argv) <= 1) {
    echo "Usage: download_idp_metadata.php destination_dir_without_trailing_slash\n";
    exit(-1);
}

$dir = $argv[1];

$idp_list_url = 'https://registry.spid.gov.it/assets/data/idp.json';
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $idp_list_url);
curl_setopt($ch, CURLOPT_FAILONERROR, 1);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
echo "Contacting $idp_list_url" . PHP_EOL;
$json = curl_exec($ch);
curl_close($ch);
$idps = json_decode($json);

foreach ($idps->data as $idp) {
    $metadata_url = $idp->metadata_url;
    $ipa_entity_code = $idp->ipa_entity_code;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $metadata_url);
    curl_setopt($ch, CURLOPT_FAILONERROR, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    echo "Contacting $metadata_url" . PHP_EOL;
    $xml = curl_exec($ch);
    $info = curl_getinfo($ch);
    echo ('curl info = ');
    var_dump($info);
    if ($xml === false) {
        echo 'Operation failed with error: ' . curl_error($ch);
    } else {
        // operation completed successfully
        $file = "$dir/$ipa_entity_code.xml";
        file_put_contents($file, $xml);
    }
    curl_close($ch);
}
