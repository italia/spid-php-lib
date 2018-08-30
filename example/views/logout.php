<?php

if (!$url = $sp->logout()) {
    echo "Not logged in !<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    echo $url;
}
