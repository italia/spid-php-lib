<?php

namespace Italia\Spid\Spid\Interfaces;

// service provider class
interface SpInterface
{
    // $settings = [
    //     'sp_entityid' => $base, // preferred: https protocol, no trailing slash
    //     'sp_key_file' => './sp.key', // absolute path or relative to service root folder
    //     'sp_cert_file' => './sp.crt', // absolute path or relative to service root folder
    //     'sp_assertionconsumerservice' => [
    //         // array of assertion consuming services
    //         // order is important ! the 0-base index in this array will be used in the calls
    //         $base . '/acs'
    //     ],
    //     'sp_singlelogoutservice' => $base . '/slo',  // path relative to sp_entityid base url or full url
    //     'sp_org_name' => 'test',
    //     'sp_org_display_name' => 'Test',
    //     'idp_metadata_folder' => './idp_metadata/',
    //     'sp_attributeconsumingservice' => [
    //         // array of attribute consuming services
    //         // order is important ! the 0-base index in this array will be used in the calls
    //         ["name", "familyName", "fiscalNumber", "email"],
    //         ["name", "familyName", "fiscalNumber", "email", "spidCode"]
    //         ]
    //     ];
    public function __construct(array $settings);

    // loads all Identity Providers metadata found in path
    public function loadIdpMetadata($path);

    // loads selected Identity Provider
    public function loadIdpFromFile($filename);

    // returns SP XML metadata as a string
    public function getSPMetadata();

    // LOW-LEVEL FUNCTION:

    // get an IdP
    // the IdP can be used to generate an AuthnRequest:
    //   $idp = getIdp('idp_1');
    //   $authnRequest = idp->$authnRequest(0, 1, 2, 'https://example.com/return_to_url');
    //   $url = $authnRequest->redirect_url();
    // $idpName: shortname of IdP, same as the name of corresponding IdP metadata file, without .xml
    public function getIdp($idpName);

    // HIGH-LEVEL FUNCTIONS:

    // performs login
    // $idpName: shortname of IdP, same as the name of corresponding IdP metadata file, without .xml
    // $ass: index of assertion consumer service as per the SP metadata
    // $attr: index of attribute consuming service as per the SP metadata
    // $level: SPID level (1, 2 or 3)
    // $returnTo: return url
    // $shouldRedirect: tells if the function shoudl emit headers and redirect to login URL or return the URL as string
    public function login($idpName, $ass, $attr, $level = 1, $redirectTo = null, $shouldRedirect = true);

    // returns false if no response from IdP is found
    // else processes the response, reports errors if any
    // and finally returns true if login was successful
    public function isAuthenticated();

    // performs logout
    public function logout();

    // returns attributes as an array or null if not authenticated
    // example: array('name' => 'Franco', 'familyName' => 'Rossi', 'fiscalNumber' => 'FFFRRR88A12T4441R',)
    public function getAttributes();
}
