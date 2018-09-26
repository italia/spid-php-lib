<?php 
$mapping = $sp->getIdpList();

if (isset($_POST) && isset($_POST['selected_idp'])) {
    if (!$url = $sp->login($_POST['selected_idp'], 0, 1, 1, null, true)) {
        echo "Already logged in !<br>";
        echo "<a href=\"/\">Home</a>";
    } else {
        echo $url;
    }
} else {
?>

<div id ='spid-button' aria-live="polite">
    <noscript>
        To use the Spid Smart Button, please enable javascript!
    </noscript>
</div>

<script>
var spid = SPID.init({
    lang: 'en',                   // opzionale
    selector: '#spid-button',  // opzionale
    method: 'POST',               // opzionale
    url: '/smart-button',                // obbligatorio
    fieldName: 'selected_idp',             // opzionale
    mapping: {                    // opzionale
        <?php 
        foreach ($mapping as $key => $value) {
            echo "'" . $value . "':" . $key . ",";
        }
        ?>
    },
    supported: [                  // obbligatorio
        <?php 
        foreach ($mapping as $key => $value) {
            echo "'" . $key . "',";
        }
        ?> 
    ],
    extraProviders: [            // opzionale
        {
            "protocols": ["SAML"],
            "entityName": "Testenv",
            "logo": "spid-idp-aruba.svg",
            "entityID": "http://0.0.0.0:8088/",
            "active": true
        },
    ],
    protocol: "SAML",
    size: "small"
});
</script>

<?php } ?>