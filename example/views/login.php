<?php

if (!$sp->login("testenv", 0, 1)) {
    echo "Already logged in !<br>";
    echo "<a href=\"/\">Home</a>";
}
