<?php
require_once(__DIR__ . "/../vendor/autoload.php");
if (file_exists(__DIR__ . "/config.php")) {
    require_once(__DIR__ . "/config.php");
}

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$base = 'https://sp.example.com';
$settings = [
    'sp_entityid' => $base,
    'sp_key_file' => './sp.key',
    'sp_cert_file' => './sp.crt',
    'sp_assertionconsumerservice' => [
        $base . '/acs'
    ],
    'sp_singlelogoutservice' => [
        [$base . '/slo', "POST"],
        [$base . '/slo', "REDIRECT"]
    ],
    'sp_org_name' => 'test',
    'sp_org_display_name' => 'Test',
    'sp_key_cert_values' => [
        'countryName' => 'IT',
        'stateOrProvinceName' => 'Milan',
        'localityName' => 'Milan',
        'commonName' => 'Name',
        'emailAddress' => 'test@test.com',
    ],
    'idp_metadata_folder' => './idp_metadata/',
    'sp_attributeconsumingservice' => [
        ["name", "familyName", "fiscalNumber", "email"],
        ["name", "familyName", "fiscalNumber", "email", "spidCode"]
    ]
];
$sp = new Italia\Spid\Sp($settings);

$request_uri = explode('?', $_SERVER['REQUEST_URI'], 2);

switch ($request_uri[0]) {
    // Home page
    case '/':
        require './views/home.php';
        break;
    // Login page
    case '/smart-button':
        require './views/smart-button.php';
        break;
    // Login page
    case '/login':
        require './views/login.php';
        break;
    // Login POST page
    case '/login-post':
        require './views/login_post.php';
        break;
    // Login Smart Button page
    case '/smart-button':
        require './views/smart_button.php';
        break;
    // Metadata page
    case '/metadata':
        require './views/metadata.php';
        break;
    // Acs page
    case '/acs':
        require './views/acs.php';
        break;
    // Logout page
    case '/logout':
        require './views/logout.php';
        break;
    // Logout POST page
    case '/logout-post':
        require './views/logout_post.php';
        break;
    // Slo page
    case '/slo':
        require './views/slo.php';
        break;
    // Everything else
    default:
        echo "404 not found";
        break;
}
