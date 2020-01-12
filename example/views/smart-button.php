<?php
$mapping = $sp->getIdpList();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">

    <link rel="stylesheet" href="views/spid-smart-button/spid-button.min.css">
    <script src="views/spid-smart-button/spid-button.min.js"></script>
    <title>Smart Button Login</title>
</head>
<body>
    <div id ='spid-button' aria-live="polite">
        <noscript>
            To use the Spid Smart Button, please enable javascript!
        </noscript>
    </div>

    <script>
    var spid = SPID.init({
        lang: 'en',
        selector: '#spid-button',
        method: 'POST',
        // POST data with the selected IdP will be sent to this URL with the name indicated in fieldName
        // In this case redirect and reuse the provided login example page
        url: '/login',
        fieldName: 'selected_idp',
        // Usiamo il mapping per stabilire la connessione tra idpEntityID
        // e il nome del file XML che contiene i suoi metadati
        mapping: {                    
            <?php
            foreach ($mapping as $key => $value) {
                echo "'" . $value . "': '" . $key . "',";
            }
            ?>
        },
        // At least one supported IdP must be provided
        supported: [
            <?php
            foreach ($mapping as $key => $value) {
                echo "'".$key."',";
            }
            ?>
        ],
        // Il campo sarebbe opzionale, ma anche se il mapping contiene testenv, la libreria smart-button sembra 
        // ignorare gli IdP non "ufficiali". extraProviders è quindi obbligatorio se vogliamo usare testenv
        extraProviders: [           
            {
                "protocols": ["SAML"],
                "entityName": "Testenv",
                "logo": "spid-idp-testenv2.svg",
                "entityID": "<?php echo $mapping['testenv'] ?>",
                "active": true
            },
        ],
        protocol: "SAML",
        size: "large"
    });
    </script>
</body>
</html>
