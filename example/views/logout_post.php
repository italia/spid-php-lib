<?php

if (!$url = $sp->logoutPost(0)) {
    echo "Not logged in !<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    echo $url;
}
