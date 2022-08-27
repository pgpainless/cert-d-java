// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pgp.cert_d.dummy.TestKeyMaterialMerger;
import pgp.cert_d.dummy.TestKeyMaterialReaderBackend;
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookup;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.Key;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;
import pgp.certificate_store.exception.NotAStoreException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pgp.cert_d.TestKeys.CEDRIC_FP;
import static pgp.cert_d.TestKeys.HARRY_FP;
import static pgp.cert_d.TestKeys.RON_FP;

public class PGPCertificateDirectoryTest {


    private static final KeyMaterialMerger merger = new TestKeyMaterialMerger();

    private static Stream<Arguments> provideTestSubjects()
            throws IOException, NotAStoreException {
        PGPCertificateDirectory inMemory = PGPCertificateDirectories.inMemoryCertificateDirectory(
                new TestKeyMaterialReaderBackend());

        File tempDir = Files.createTempDirectory("pgp-cert-d-test").toFile();
        tempDir.deleteOnExit();
        PGPCertificateDirectory fileBased = PGPCertificateDirectories.fileBasedCertificateDirectory(
                new TestKeyMaterialReaderBackend(),
                tempDir,
                new InMemorySubkeyLookup());

        return Stream.of(
                Arguments.of(Named.of("InMemoryCertificateDirectory", inMemory)),
                Arguments.of(Named.of("FileBasedCertificateDirectory", fileBased)));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getNonExistentCertByFingerprintThrowsNoSuchElementException(PGPCertificateDirectory directory) {
        assertThrows(NoSuchElementException.class, () ->
                directory.getByFingerprint("0000000000000000000000000000000000000000"));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getNonExistentCertByFingerprintIfChangedThrowsNoSuchElementException(PGPCertificateDirectory directory) {
        assertThrows(NoSuchElementException.class, () ->
                directory.getByFingerprintIfChanged("0000000000000000000000000000000000000000", 12));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getNonExistentCertBySpecialNameThrowsNoSuchElementException(PGPCertificateDirectory directory) {
        assertThrows(NoSuchElementException.class, () ->
                directory.getBySpecialName(SpecialNames.TRUST_ROOT));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getNonExistentCertBySpecialNameIfChangedThrowsNoSuchElementException(PGPCertificateDirectory directory) {
        assertThrows(NoSuchElementException.class, () ->
                directory.getBySpecialNameIfChanged(SpecialNames.TRUST_ROOT, 12));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getNonExistentTrustRootThrowsNoSuchElementException(PGPCertificateDirectory directory) {
        assertThrows(NoSuchElementException.class, () ->
                directory.getTrustRoot());
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getNonExistentTrustRootIfChangedThrowsNoSuchElementException(PGPCertificateDirectory directory) {
        assertThrows(NoSuchElementException.class, () ->
                directory.getTrustRootCertificateIfChanged(12));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getNonExistentTrustRootCertificateThrowsNoSuchElementException(PGPCertificateDirectory directory) {
        assertThrows(NoSuchElementException.class, () ->
                directory.getTrustRootCertificate());
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void lockDirectoryAndTryInsertWillFail(PGPCertificateDirectory directory)
            throws IOException, InterruptedException, BadDataException {
        // Manually lock the dir
        assertFalse(directory.backend.getLock().isLocked());
        directory.backend.getLock().lockDirectory();
        assertTrue(directory.backend.getLock().isLocked());
        assertFalse(directory.backend.getLock().tryLockDirectory());

        Certificate inserted = directory.tryInsert(TestKeys.getCedricCert(), merger);
        assertNull(inserted);

        directory.backend.getLock().releaseDirectory();
        inserted = directory.tryInsert(TestKeys.getCedricCert(), merger);
        assertNotNull(inserted);
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void lockDirectoryAndTryInsertTrustRootWillFail(PGPCertificateDirectory directory)
            throws IOException, InterruptedException, BadDataException {
        // Manually lock the dir
        assertFalse(directory.backend.getLock().isLocked());
        directory.backend.getLock().lockDirectory();
        assertTrue(directory.backend.getLock().isLocked());

        KeyMaterial inserted = directory.tryInsertTrustRoot(TestKeys.getHarryKey(), merger);
        assertNull(inserted);

        directory.backend.getLock().releaseDirectory();
        inserted = directory.tryInsertTrustRoot(TestKeys.getHarryKey(), merger);
        assertNotNull(inserted);
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void lockDirectoryAndTryInsertWithSpecialNameWillFail(PGPCertificateDirectory directory)
            throws IOException, InterruptedException, BadDataException, BadNameException {
        // Manually lock the dir
        assertFalse(directory.backend.getLock().isLocked());
        directory.backend.getLock().lockDirectory();
        assertTrue(directory.backend.getLock().isLocked());

        Certificate inserted = directory.tryInsertWithSpecialName(SpecialNames.TRUST_ROOT, TestKeys.getHarryKey(), merger);
        assertNull(inserted);

        directory.backend.getLock().releaseDirectory();
        inserted = directory.tryInsertWithSpecialName(SpecialNames.TRUST_ROOT, TestKeys.getHarryKey(), merger);
        assertNotNull(inserted);
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void getByInvalidNameFails(PGPCertificateDirectory directory) {
        assertThrows(BadNameException.class, () -> directory.getBySpecialName("invalid"));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testInsertAndGetSingleCert(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException, BadNameException {
        assertThrows(NoSuchElementException.class, () -> directory.getByFingerprint(CEDRIC_FP), "Empty directory MUST NOT contain certificate");

        Certificate certificate = directory.insert(TestKeys.getCedricCert(), merger);
        assertEquals(CEDRIC_FP, certificate.getFingerprint(), "Fingerprint of inserted cert MUST match");

        Certificate get = directory.getByFingerprint(CEDRIC_FP);
        assertEquals(CEDRIC_FP, get.getFingerprint(), "Fingerprint of retrieved cert MUST match");

        byte[] expected = TestKeys.CEDRIC_CERT.getBytes(Charset.forName("UTF8"));
        ByteArrayOutputStream actual = new ByteArrayOutputStream();
        Streams.pipeAll(get.getInputStream(), actual);
        assertArrayEquals(expected, actual.toByteArray(), "InputStream of cert MUST match what we gave in");
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testInsertAndGetTrustRootAndCert(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException {
        assertThrows(NoSuchElementException.class, () -> directory.getTrustRoot());

        KeyMaterial trustRootMaterial = directory.insertTrustRoot(
                TestKeys.getHarryKey(), merger);
        assertNotNull(trustRootMaterial);
        assertTrue(trustRootMaterial instanceof Key);
        assertEquals(HARRY_FP, trustRootMaterial.getFingerprint());

        Key trustRoot = (Key) directory.getTrustRoot();
        assertEquals(HARRY_FP, trustRoot.getFingerprint());
        Certificate trustRootCert = directory.getTrustRootCertificate();
        assertEquals(HARRY_FP, trustRootCert.getFingerprint());

        directory.tryInsert(TestKeys.getRonCert(), merger);
        directory.insert(TestKeys.getCedricCert(), merger);

        Set<String> expected = new HashSet<>(Arrays.asList(RON_FP, CEDRIC_FP));

        Set<String> actual = new HashSet<>();
        Iterator<String> fingerprints = directory.fingerprints();
        actual.add(fingerprints.next());
        actual.add(fingerprints.next());
        assertFalse(fingerprints.hasNext());

        assertEquals(expected, actual);
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testGetTrustRootIfChanged(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException {
        KeyMaterial trustRootMaterial = directory.insertTrustRoot(
                TestKeys.getHarryKey(), merger);

        assertNotNull(trustRootMaterial.getTag());
        Long tag = trustRootMaterial.getTag();
        assertNull(directory.getTrustRootCertificateIfChanged(tag));
        assertNotNull(directory.getTrustRootCertificateIfChanged(tag + 1));

        Long oldTag = tag;
        Thread.sleep(10);
        // "update" key
        trustRootMaterial = directory.insertTrustRoot(
                TestKeys.getHarryKey(), merger);
        tag = trustRootMaterial.getTag();

        assertNotEquals(oldTag, tag);
        assertNotNull(directory.getTrustRootCertificateIfChanged(oldTag));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testGetBySpecialNameIfChanged(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException, BadNameException {
        KeyMaterial specialName = directory.insertWithSpecialName(SpecialNames.TRUST_ROOT,
                TestKeys.getHarryKey(), merger);

        assertNotNull(specialName.getTag());
        Long tag = specialName.getTag();
        assertNull(directory.getBySpecialNameIfChanged(SpecialNames.TRUST_ROOT, tag));
        assertNotNull(directory.getBySpecialNameIfChanged(SpecialNames.TRUST_ROOT, tag + 1));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testGetByFingerprintIfChanged(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException, BadNameException {
        Certificate certificate = directory.insert(TestKeys.getCedricCert(), merger);
        Long tag = certificate.getTag();
        assertNotNull(tag);

        assertNull(directory.getByFingerprintIfChanged(certificate.getFingerprint(), tag));
        assertNotNull(directory.getByFingerprintIfChanged(certificate.getFingerprint(), tag + 1));
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testOverwriteTrustRoot(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException {
        directory.insertTrustRoot(TestKeys.getHarryKey(), merger);
        assertEquals(HARRY_FP, directory.getTrustRoot().getFingerprint());
        assertTrue(directory.getTrustRoot() instanceof Key);

        directory.insertTrustRoot(TestKeys.getCedricCert(), merger);
        assertEquals(CEDRIC_FP, directory.getTrustRoot().getFingerprint());
        assertTrue(directory.getTrustRoot() instanceof Certificate);
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testOverwriteSpecialName(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException, BadNameException {
        directory.insertWithSpecialName(SpecialNames.TRUST_ROOT, TestKeys.getRonCert(), merger);
        KeyMaterial bySpecialName = directory.getBySpecialName(SpecialNames.TRUST_ROOT);
        assertEquals(RON_FP, bySpecialName.getFingerprint());

        directory.insertWithSpecialName(SpecialNames.TRUST_ROOT, TestKeys.getHarryKey(), merger);
        assertEquals(HARRY_FP, directory.getBySpecialName(SpecialNames.TRUST_ROOT).getFingerprint());
    }

    @ParameterizedTest
    @MethodSource("provideTestSubjects")
    public void testOverwriteByFingerprint(PGPCertificateDirectory directory)
            throws BadDataException, IOException, InterruptedException, BadNameException {
        directory.insert(TestKeys.getRonCert(), merger);
        Certificate extracted = directory.getByFingerprint(RON_FP);
        assertEquals(RON_FP, extracted.getFingerprint());

        directory.insert(TestKeys.getRonCert(), merger);
        extracted = directory.getByFingerprint(RON_FP);
        assertEquals(RON_FP, extracted.getFingerprint());
    }

}
