<?php
// The Identity Provider is chosen with an identifier that must appear in the
// server side list built from the metadata the deployment trusts. Never hand a
// value taken from the request straight to login(): the metadata of the selected
// Identity Provider supplies the certificate used to validate the SAML Response.
$availableIdps = array_keys($sp->getIdpList());
$idp = 'testenv';
if (isset($_POST) && isset($_POST['selected_idp']) && in_array($_POST['selected_idp'], $availableIdps, true)) {
    $idp = $_POST['selected_idp'];
}

if (!$url = $sp->login($idp, 0, 1, 1, null, true)) {
    echo "Already logged in !<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    echo $url;
}
