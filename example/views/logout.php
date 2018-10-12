<?php

if (!$url = $sp->logout(0)) {
    echo "Not logged in !<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    echo $url;
}
