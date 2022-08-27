// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import pgp.cert_d.backend.FileBasedCertificateDirectoryBackend;
import pgp.cert_d.dummy.TestKeyMaterialMerger;
import pgp.cert_d.dummy.TestKeyMaterialReaderBackend;
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookup;
import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;
import pgp.certificate_store.exception.NotAStoreException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class FileBasedPGPCertificateDirectoryTest {

    private static final KeyMaterialMerger merger = new TestKeyMaterialMerger();
    @Test
    public void testFileBasedCertificateDirectoryTagChangesWhenFileChanges()
            throws IOException, NotAStoreException, BadDataException, InterruptedException, BadNameException {
        File tempDir = Files.createTempDirectory("file-based-changes").toFile();
        tempDir.deleteOnExit();
        PGPCertificateDirectory directory = PGPCertificateDirectories.fileBasedCertificateDirectory(
                new TestKeyMaterialReaderBackend(),
                tempDir,
                new InMemorySubkeyLookup());
        FileBasedCertificateDirectoryBackend.FilenameResolver resolver =
                new FileBasedCertificateDirectoryBackend.FilenameResolver(tempDir);

        // Insert certificate
        Certificate certificate = directory.insert(TestKeys.getCedricCert(), merger);
        Long tag = certificate.getTag();
        assertNotNull(tag);
        assertNull(directory.getByFingerprintIfChanged(certificate.getFingerprint(), tag));

        Long oldTag = tag;

        Thread.sleep(10);
        // Change the file on disk directly, this invalidates the tag due to changed modification date
        File certFile = resolver.getCertFileByFingerprint(certificate.getFingerprint());
        FileOutputStream fileOut = new FileOutputStream(certFile);
        Streams.pipeAll(certificate.getInputStream(), fileOut);
        fileOut.write("\n".getBytes());
        fileOut.close();

        // Old invalidated tag indicates a change, so the modified certificate is returned
        certificate = directory.getByFingerprintIfChanged(certificate.getFingerprint(), oldTag);
        assertNotNull(certificate);

        // new tag is valid
        tag = certificate.getTag();
        assertNotEquals(oldTag, tag);
        assertNull(directory.getByFingerprintIfChanged(certificate.getFingerprint(), tag));
    }

    @Test
    public void fileBasedStoreInWriteProtectedAreaThrows() {
        File root = new File("/");
        assumeTrue(root.exists(), "This test only runs on unix-like systems");
        File baseDirectory = new File(root, "pgp.cert.d");
        assumeFalse(baseDirectory.mkdirs(), "This test assumes that we cannot create dirs in /");

        KeyMaterialReaderBackend reader = new TestKeyMaterialReaderBackend();
        SubkeyLookup lookup = new InMemorySubkeyLookup();
        assertThrows(NotAStoreException.class, () -> PGPCertificateDirectories.fileBasedCertificateDirectory(
                reader, baseDirectory, lookup));
    }

    @Test
    public void fileBasedStoreOnFileThrows()
            throws IOException {
        File tempDir = Files.createTempDirectory("containsAFile").toFile();
        tempDir.deleteOnExit();
        File baseDir = new File(tempDir, "pgp.cert.d");
        baseDir.createNewFile(); // this is a file, not a dir

        KeyMaterialReaderBackend reader = new TestKeyMaterialReaderBackend();
        SubkeyLookup lookup = new InMemorySubkeyLookup();
        assertThrows(NotAStoreException.class, () -> PGPCertificateDirectories.fileBasedCertificateDirectory(
                reader, baseDir, lookup));
    }

    @Test
    public void testCertificateStoredUnderWrongFingerprintThrowsBadData()
            throws IOException, NotAStoreException, BadDataException, InterruptedException, BadNameException {
        File tempDir = Files.createTempDirectory("wrong-fingerprint").toFile();
        tempDir.deleteOnExit();
        PGPCertificateDirectory directory = PGPCertificateDirectories.fileBasedCertificateDirectory(
                new TestKeyMaterialReaderBackend(),
                tempDir,
                new InMemorySubkeyLookup());
        FileBasedCertificateDirectoryBackend.FilenameResolver resolver =
                new FileBasedCertificateDirectoryBackend.FilenameResolver(tempDir);

        // Insert Rons certificate
        directory.insert(TestKeys.getRonCert(), merger);

        // Copy Rons cert to Cedrics cert file
        File ronCert = resolver.getCertFileByFingerprint(TestKeys.RON_FP);
        FileInputStream inputStream = new FileInputStream(ronCert);
        File cedricCert = resolver.getCertFileByFingerprint(TestKeys.CEDRIC_FP);
        cedricCert.getParentFile().mkdirs();
        cedricCert.createNewFile();
        FileOutputStream outputStream = new FileOutputStream(cedricCert);
        Streams.pipeAll(inputStream, outputStream);
        inputStream.close();
        outputStream.close();

        // Reading cedrics cert will fail, as it has Rons fingerprint
        assertThrows(BadDataException.class, () -> directory.getByFingerprint(TestKeys.CEDRIC_FP));
    }
}
