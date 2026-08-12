<?php

declare(strict_types=1);

use Italia\Spid\Spid\Saml;
use Italia\Spid\Spid\Saml\Idp;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SamlFixture.php';

/**
 * Regression tests for the arbitrary Identity Provider metadata loading reported
 * against f5899ebcac646506c80a078fa2f415ed59605952.
 *
 * Idp::loadFromXml() used the caller supplied value as a file name as soon as it
 * contained the configured metadata folder anywhere inside it, and then handed it
 * to file_exists()/simplexml_load_file(). Since the X.509 certificate found in
 * that metadata is the trust anchor used to validate the SAML Response, choosing
 * the file means choosing who may authenticate users.
 */
final class IdpMetadataTest extends TestCase
{
    /** @var SamlFixture */
    private static $f;
    /** @var Saml */
    private static $saml;

    public static function setUpBeforeClass(): void
    {
        self::$f = new SamlFixture('spid_idp_metadata');
        self::$saml = new Saml(self::$f->settings, false);

        // A rogue metadata file, with the attacker's own certificate, reachable on
        // the filesystem but outside the configured folder.
        $rogue = SamlFixture::keyPair('rogue.example.com');
        file_put_contents(self::$f->dir . '/rogue.xml', self::$f->metadataFor($rogue['cert']));
        // ... and one whose path contains the metadata folder name as a substring,
        // which is exactly what the old check tested for.
        @mkdir(self::$f->dir . '/idp_metadata_evil');
        file_put_contents(
            self::$f->dir . '/idp_metadata_evil/idp.xml',
            self::$f->metadataFor($rogue['cert'])
        );
        @symlink(self::$f->dir . '/rogue.xml', self::$f->dir . '/idp_metadata/linked.xml');
        @mkdir(self::$f->dir . '/idp_metadata/directory.xml');
    }

    public static function tearDownAfterClass(): void
    {
        self::$f->cleanUp();
    }

    private function load(string $value): Idp
    {
        $idp = new Idp(self::$saml);
        return $idp->loadFromXml($value);
    }

    public function testBareIdentifierIsAccepted(): void
    {
        $idp = $this->load('idp');
        $this->assertSame('idp', $idp->idpFileName);
        $this->assertSame(self::$f->idpEntityId, $idp->metadata['idpEntityId']);
    }

    public function testIdentifierWithExtensionIsAccepted(): void
    {
        $this->assertSame('idp', $this->load('idp.xml')->idpFileName);
    }

    // getIdpList() enumerates the folder with glob() and passes full paths.
    public function testPathInsideTheConfiguredFolderIsAccepted(): void
    {
        $idp = $this->load(self::$f->dir . '/idp_metadata/idp.xml');
        $this->assertSame('idp', $idp->idpFileName, 'the session must hold the identifier, not the path');
    }

    /**
     * @dataProvider rejectedValues
     */
    public function testRejectedValues(string $value): void
    {
        $this->expectException(\Exception::class);
        $this->load($value);
    }

    public function rejectedValues(): array
    {
        // The folder the tests configure; used to build the values whose path
        // contains it literally, the case the old substring check accepted.
        $folder = sys_get_temp_dir() . '/spid_idp_metadata_' . getmypid() . '/idp_metadata/';

        return [
            'unknown identifier' => ['not-a-configured-idp'],
            'empty' => [''],
            'traversal' => ['../rogue'],
            'traversal with extension' => ['../rogue.xml'],
            'traversal through the folder' => [$folder . '../rogue.xml'],
            'deep traversal' => [$folder . '../../../../etc/passwd'],
            'absolute path outside' => ['/etc/passwd'],
            'windows style path' => ['C:\\Windows\\Temp\\rogue.xml'],
            'sibling folder with matching prefix' => [$folder . '_evil/idp.xml'],
            'file scheme' => ['file://' . $folder . 'idp.xml'],
            'ftp scheme' => ['ftp://attacker.example' . $folder . 'idp.xml'],
            'http scheme' => ['http://attacker.example' . $folder . 'idp.xml'],
            'https scheme' => ['https://attacker.example' . $folder . 'idp.xml'],
            'php filter wrapper' => ['php://filter/resource=' . $folder . 'idp.xml'],
            'data wrapper' => ['data://text/plain;base64,PG1kOkVudGl0eURlc2NyaXB0b3I+'],
            'phar wrapper' => ['phar://' . $folder . 'rogue.phar/idp.xml'],
            'symlink out of the folder' => ['linked'],
            'directory named like a metadata file' => ['directory'],
            'nul byte' => ["idp\0.xml"],
        ];
    }

    // The certificate actually used to validate a Response must be the one of the
    // Identity Provider the server selected, never one supplied through the
    // parameter used to pick it.
    public function testTheTrustAnchorAlwaysComesFromTheConfiguredFolder(): void
    {
        $expected = file_get_contents(self::$f->idpCert);
        $loaded = $this->load('idp')->metadata['idpCertValue'];

        $normalize = function ($pem) {
            return preg_replace('/\s+/', '', $pem);
        };
        $this->assertSame($normalize($expected), $normalize($loaded));
    }
}
