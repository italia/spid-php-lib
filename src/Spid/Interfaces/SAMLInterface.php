<?php

namespace Italia\Spid\Spid\Interfaces;

// service provider class
use Italia\Spid\Spid\Saml\Idp;

interface SAMLInterface
{
    // $settings = [
    //     'sp_entityid' => $base, // preferred: https protocol, no trailing slash
    //     'sp_key_file' => './sp.key',
    //     'sp_cert_file' => './sp.crt',
    //     'sp_assertionconsumerservice' => [
    //         // array of assertion consuming services
    //         // order is important ! the 0-base index in this array will be used in the calls
    //         $base . '/acs_route'
    //     ],
    //     'sp_singlelogoutservice' => $base . '/slo_route',  // path relative to sp_entityid base url or full url
    //     'sp_org_name' => 'your organization full name',
    //     'sp_org_display_name' => 'your organization display name',
    //     'idp_metadata_folder' => './idp_metadata/', // path to idp metadata folder
    //     'sp_attributeconsumingservice' => [
    //         // array of attribute consuming services
    //         // order is important ! the 0-base index in this array will be used in the calls
    //         ["name", "familyName", "fiscalNumber", "email"],
    //         ["name", "familyName", "fiscalNumber", "email", "spidCode"]
    //         ]
    //     ];
    public function __construct(array $settings);

    // loads selected Identity Provider
    // $filename: file name of the idp to be loaded. Only the file, without the path, needs to be provided.
    // returns null or the Idp object. 
    public function loadIdpFromFile($filename);

    // loads all Idps found in the idp metadata folder provided in settings
    // files are loaded with loadIdpFromFile($filename)
    // returns an array mapping entityID => filename (used for spid-smart-button)
    // if no idps are found returns an empty array
    public function getIdpList() : array;

    // alias of loadIdpFromFile
    public function getIdp($filename);

    // returns SP XML metadata as a string
    public function getSPMetadata() : string;
    
    // performs login
    // $idpName: shortname of IdP, same as the name of corresponding IdP metadata file, without .xml
    // $ass: index of assertion consumer service as per the SP metadata
    // $attr: index of attribute consuming service as per the SP metadata
    // $level: SPID level (1, 2 or 3)
    // $returnTo: return url
    // $shouldRedirect: tells if the function should emit headers and redirect to login URL or return the URL as string
    // returns false is already logged in
    // returns an empty string if $shouldRedirect = true, the login URL otherwhise
    public function login($idpName, $ass, $attr, $level = 1, $redirectTo = null, $shouldRedirect = true);

    // performs login with POST Binding
    // uses the same parameters and return values as login
    public function loginPost($idpName, $ass, $attr, $level = 1, $redirectTo = null, $shouldRedirect = true);

    // This method takes the necessary steps to update the user login status, and return a boolean representing the result
    // The method checks for any input response and validates it. The validation itself can create or destroy login sessions.
    // After updating the login status as described, return true if login session exists, false otherwise
    // IMPORTANT NOTICE: AFTER ANY LOGIN/LOGOUT OPERATION YOU MUST CALL THIS METHOD TO FINALIZE THE OPERATION
    // CALLING THIS METHOD AFTER LOGIN() WILL IN FACT FINISH THE OPERATION BY VALIDATING THE RESULT AND CREATING THE SESSION
    // AND STORING USER ATTRIBUTES.
    // SIMILARLY, AFTER A LOGOUT() CALLING THIS METHOD WILL VALIDATE THE RESULT AND DESTROY THE SESSION.
    // LOGIN() AND LOGOUT() ALONE INTERACT WITH THE IDP, BUT DON'T CHECK FOR RESULTS AND UPDATE THE SP
    public function isAuthenticated() : bool;

    // performs logout
    // $returnTo: return url
    // $shouldRedirect: tells if the function should emit headers and redirect to login URL or return the URL as string
    // returns false if not logged in
    // returns an empty string if $shouldRedirect = true, the logout URL otherwhise
    public function logout($redirectTo = null, $shouldRedirect = true);

    // performs logout with POST Binding
    // uses the same parameters and return values as logout
    public function logoutPost($redirectTo = null, $shouldRedirect = true);

    // returns attributes as an array or null if not authenticated
    // example: array('name' => 'Franco', 'familyName' => 'Rossi', 'fiscalNumber' => 'FFFRRR88A12T4441R',)
    public function getAttributes() : array;
}
