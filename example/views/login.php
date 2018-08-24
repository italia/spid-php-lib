<?php

if (!$sp->login(IDP_METADATA_NAME, 0, 1)) {
    echo "Already logged in !<br>";
    echo "<a href=\"/\">Home</a>";
}
