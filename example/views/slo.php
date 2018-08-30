<?php
print_r($_SESSION);

echo "<br>";

print_r($_POST);
print_r($_GET);
die;
if ($sp->isAuthenticated()) {
    echo "Logout failed!<br>";
    echo "<a href=\"/\">Home</a>";
} else {
    echo "Logout succesful!<br>";
    echo "<a href=\"/Home\">Home</a>";
}
