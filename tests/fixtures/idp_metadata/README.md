# IdP metadata fixtures

These files are the metadata the unit tests run against. They are committed on purpose: the test
suite must not depend on the availability of `registry.spid.gov.it`, on the shape of its payload,
or on the DNS choices of the individual Identity Providers. The live registry is exercised by the
separate `registry-smoke` job in [.github/workflows/test.yml](../../../.github/workflows/test.yml).

They were generated from the SPID registry (`https://registry.spid.gov.it/entities-idp?output=json`)
and carry the real entityID, SSO/SLO endpoints and signing certificates of three production IdPs,
chosen to cover the shapes the parser has to handle:

| File | entityID | why it is here |
|:---|:---|:---|
| `posteid.xml` | `https://posteid.poste.it` | the ordinary case; the registry publishes two signing certificates for it, one of them expired, so it also covers the certificate selection |
| `intesigroup.xml` | `https://idp.intesigroup.com` | serves SSO/SLO from `spid.intesigroup.com`, a different host than the entityID (see [issue #148](https://github.com/italia/spid-php-lib/issues/148)) |
| `lepida.xml` | `https://id.lepida.it/idp/shibboleth` | entityID with a path component, not a bare origin |

To refresh them, rebuild the files with
[bin/download_idp_metadata.php](../../../bin/download_idp_metadata.php) and copy over the three
entries above. Nothing in the suite asserts that the certificates are still valid — that check
belongs to the `registry-smoke` job, which runs against the live registry — so a refresh is only
needed when the shape of the metadata changes.
