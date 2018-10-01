<?php

if (!$url = $sp->logoutPost()) {
    echo "Not logged in !<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    echo $url;
}
