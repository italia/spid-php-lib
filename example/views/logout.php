<?php

if (!$sp->logout()) {
    echo "Not logged in !<br>";
    echo "<a href=\"/\">Home</a>";
}
