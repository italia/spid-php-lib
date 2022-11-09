<?php
include_once './model/Db.php';

if (isset($_POST) && isset($_POST['selected_idp'])) {
    $idp = $_POST['selected_idp'];
}
if (isset($_GET) && isset($_GET['selected_idp'])) {
    $idp = $_GET['selected_idp'];
}

if (!$url = $sp->login($idp ?? 'testenv', 0, 1, 1, null, true)) {
    echo "Already logged in !<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    if (isset($settings['database'])) {
		$db = new Db($sp->getIdp($idp));
		$db->insertAuthnDataIntoLog();
	}
    echo $url;
}
