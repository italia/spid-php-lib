<?php

if ($sp->isAuthenticated()) {
    echo "Logout failed!<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    echo "Logout succesful!<br>";
    echo "<a href=\"/\">Home</a>";
}
