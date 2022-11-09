<?php
include_once './model/Db.php';

if ($sp->isAuthenticated()) {

    if (isset($settings['database']) && !empty($sp->getResponse())) {
        $selectedIdp = $_SESSION['idpName'] ?? $_SESSION['spidSession']['idp'];
        $db = new Db($sp->getIdp($selectedIdp));
        $db->updateLogWithResponseData($sp->getResponse());
    }

    foreach ($sp->getAttributes() as $key => $attr) {
        echo $key . ' - ' . $attr . '<br>';
    }
    echo "<a href=\"/\">Home</a>";
} else {
    echo "Not logged in !<br>";
    echo "<a href=\"/login\">Login</a>";
}
