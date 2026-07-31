#!/usr/bin/env php
<?php
// downloads the metadata for all current production IdPs from the registry
// and stores them all in the specified directory
//
// The old registry endpoint https://registry.spid.gov.it/assets/data/idp.json is gone
// (it answers HTTP 405) and the registry no longer publishes a per-IdP metadata_url.
// The current endpoint https://registry.spid.gov.it/entities-idp?output=json returns, for
// every registered IdP, the entityID, the SSO/SLO services and the signing certificates,
// which is exactly the subset of the SAML metadata this library consumes: see
// Italia\Spid\Spid\Saml\Idp::loadFromXml(). The metadata files are therefore rebuilt
// locally from the registry payload instead of being fetched from each IdP; the trust
// anchor is the TLS connection to the SPID registry.
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

if (!is_dir($dir)) {
    fwrite(STDERR, "Destination directory $dir does not exist" . PHP_EOL);
    exit(1);
}

$idp_list_url = 'https://registry.spid.gov.it/entities-idp?output=json';
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $idp_list_url);
curl_setopt($ch, CURLOPT_FAILONERROR, 1);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json'));
echo "Contacting $idp_list_url" . PHP_EOL;
$json = curl_exec($ch);
if ($json === false) {
    fwrite(STDERR, 'Could not fetch the IdP list: ' . curl_error($ch) . PHP_EOL);
    curl_close($ch);
    exit(1);
}
curl_close($ch);

$idps = json_decode($json, true);
if (!is_array($idps) || count($idps) == 0) {
    fwrite(STDERR, "The IdP list at $idp_list_url is empty or is not valid JSON" . PHP_EOL);
    exit(1);
}

// closures rather than named functions: this file already executes logic, and PSR-1
// asks a file to either declare symbols or run code, not both
$xmlAttr = function ($value) {
    return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
};

// Italia\Spid\Spid\Saml\Idp::loadFromXml() reads ONLY the first <ds:X509Certificate> of the
// document, and the registry does not order signing_certificate_x509 by validity: for more than
// one production IdP the first entry is an expired certificate and the live one comes second.
// Emitting them verbatim would hand the library a stale certificate and make every SAML response
// from that IdP fail signature validation, so drop the expired ones here.
$signingCerts = function ($certs, $entityId) {
    $valid = array();
    $expired = array();
    foreach ($certs as $cert) {
        $clean = preg_replace('/\s+/', '', $cert);
        if ($clean === '' || preg_match('/^[A-Za-z0-9+\/=]+$/', $clean) !== 1) {
            fwrite(STDERR, "Ignoring a malformed signing certificate of $entityId" . PHP_EOL);
            continue;
        }
        $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split($clean, 64, "\n") . "-----END CERTIFICATE-----\n";
        $parsed = openssl_x509_parse($pem);
        if ($parsed === false) {
            fwrite(STDERR, "Ignoring an unparseable signing certificate of $entityId" . PHP_EOL);
            continue;
        }
        if (isset($parsed['validTo_time_t']) && $parsed['validTo_time_t'] < time()) {
            $expired[] = $clean;
            continue;
        }
        $valid[] = $clean;
    }
    if (count($valid) > 0) {
        return $valid;
    }
    // nothing usable left: keep whatever the registry published rather than silently dropping the
    // IdP, but make very clear that authentication against it cannot work
    fwrite(STDERR, "WARNING: $entityId publishes no currently valid signing certificate" . PHP_EOL);
    return $expired;
};

$serviceElements = function ($tag, $services) use ($xmlAttr) {
    $out = '';
    if (!is_array($services)) {
        return $out;
    }
    foreach ($services as $service) {
        if (!isset($service['Binding']) || !isset($service['Location'])) {
            continue;
        }
        $out .= '      <md:' . $tag . ' Binding="' . $xmlAttr($service['Binding']) .
            '" Location="' . $xmlAttr($service['Location']) . '"/>' . PHP_EOL;
    }
    return $out;
};

$written = 0;
$writtenFiles = array();
foreach ($idps as $idp) {
    $entityId = isset($idp['entity_id']) ? $idp['entity_id'] : '(unnamed entity)';
    // strict string comparison: '!=' would compare as numbers should the registry ever switch
    // to integer or boolean flags, and it does so differently on PHP 7.4 and on 8.x
    $deleted = isset($idp['_deleted']) ? (string) $idp['_deleted'] : 'N';
    $disabled = isset($idp['_disabled']) ? (string) $idp['_disabled'] : 'N';
    if ($deleted !== 'N' || $disabled !== 'N') {
        echo "Skipping deleted or disabled entity $entityId" . PHP_EOL;
        continue;
    }
    if (empty($idp['entity_id']) || empty($idp['signing_certificate_x509'])
        || empty($idp['single_sign_on_service']) || empty($idp['single_logout_service'])) {
        fwrite(STDERR, 'Skipping incomplete registry entry: ' . json_encode($idp) . PHP_EOL);
        continue;
    }

    $certs = '';
    foreach ($signingCerts($idp['signing_certificate_x509'], $entityId) as $cert) {
        $certs .= '        <ds:X509Certificate>' . $xmlAttr($cert) . '</ds:X509Certificate>' . PHP_EOL;
    }
    if ($certs === '') {
        fwrite(STDERR, "Skipping $entityId: no usable signing certificate" . PHP_EOL);
        continue;
    }

    $xml = '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL
        . '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"' . PHP_EOL
        . '  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"' . PHP_EOL
        . '  entityID="' . $xmlAttr($entityId) . '">' . PHP_EOL
        . '  <md:IDPSSODescriptor WantAuthnRequestsSigned="true"' . PHP_EOL
        . '    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' . PHP_EOL
        . '    <md:KeyDescriptor use="signing">' . PHP_EOL
        . '      <ds:KeyInfo>' . PHP_EOL
        . '        <ds:X509Data>' . PHP_EOL
        . $certs
        . '        </ds:X509Data>' . PHP_EOL
        . '      </ds:KeyInfo>' . PHP_EOL
        . '    </md:KeyDescriptor>' . PHP_EOL
        . $serviceElements('SingleLogoutService', $idp['single_logout_service'])
        . '    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        . '</md:NameIDFormat>' . PHP_EOL
        . $serviceElements('SingleSignOnService', $idp['single_sign_on_service'])
        . '  </md:IDPSSODescriptor>' . PHP_EOL
        . '</md:EntityDescriptor>' . PHP_EOL;

    if (empty($idp['file_name']) && empty($idp['code'])) {
        fwrite(STDERR, "Skipping $entityId: the registry gives it neither a file_name nor a code" . PHP_EOL);
        continue;
    }
    // basename(): the file name comes from a remote payload and must not escape $dir
    $fileName = empty($idp['file_name']) ? $idp['code'] . '.xml' : basename($idp['file_name']);
    $file = "$dir/$fileName";
    if (file_put_contents($file, $xml) === false) {
        fwrite(STDERR, "Could not write $file" . PHP_EOL);
        exit(1);
    }
    echo "Wrote $file for $entityId" . PHP_EOL;
    $writtenFiles[] = realpath($file);
    $written++;
}

if ($written == 0) {
    fwrite(STDERR, "No IdP metadata could be written to $dir" . PHP_EOL);
    exit(1);
}

// Files are never deleted: the destination directory belongs to the operator. But Saml::getIdpList()
// globs the whole folder, so any leftover keeps a decommissioned IdP selectable with whatever
// certificate it had at the last run. Two things produce leftovers: an IdP leaving the registry, and
// the file naming of this script, which follows the registry and changed with it (the old endpoint
// named the files after ipa_entity_code, "idp_1.xml" and friends; the current one returns file_name,
// "01114601006.xml"), so the first run after an upgrade duplicates every IdP.
$stale = array_diff(array_map('realpath', glob("$dir/*.xml")), $writtenFiles);
foreach ($stale as $file) {
    fwrite(STDERR, "WARNING: $file was not written by this run, remove it by hand" . PHP_EOL);
}

echo "Wrote $written IdP metadata files to $dir" . PHP_EOL;
