<?php

if (!$sp->login('idp_testenv2', 0, 1)) {
    echo "Already logged in !<br>";
    echo "<a href=\"/\">Home</a>";
}
