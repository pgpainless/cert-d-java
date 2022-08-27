// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pgp.cert_d.backend.InMemoryCertificateDirectoryBackend;
import pgp.cert_d.dummy.TestKeyMaterialMerger;
import pgp.cert_d.dummy.TestKeyMaterialReaderBackend;
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookupFactory;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PGPCertificateStoreAdapterTest {

    private PGPCertificateDirectory directory;
    private PGPCertificateStoreAdapter adapter;

    private static final TestKeyMaterialMerger merger = new TestKeyMaterialMerger();

    @BeforeEach
    public void setup() {
        directory = new PGPCertificateDirectory(
                new InMemoryCertificateDirectoryBackend(new TestKeyMaterialReaderBackend()),
                new InMemorySubkeyLookupFactory().createFileBasedInstance(null));
        adapter = new PGPCertificateStoreAdapter(directory);
    }

    @Test
    public void testBadFPWithInvalidCharsYieldsBadNameException() {
        assertThrows(BadNameException.class, () -> adapter.getCertificate("XYZ78fd17f207fdf62f7976c4e9d98917ad84522"));
    }

    @Test
    public void testBadFPWithTooFewCharsYieldsBadNameException() {
        assertThrows(BadNameException.class, () -> adapter.getCertificate("23578fd17f207fdf62f7976c4e9d98917ad"));
    }

    @Test
    public void testInsertGetCertificate()
            throws BadDataException, IOException, InterruptedException, BadNameException {
        assertThrows(NoSuchElementException.class, () -> adapter.getCertificate(TestKeys.CEDRIC_FP));
        assertFalse(adapter.getCertificates().hasNext());

        Certificate certificate = adapter.insertCertificate(TestKeys.getCedricCert(), merger);
        assertNotNull(certificate);
        assertEquals(TestKeys.CEDRIC_FP, certificate.getFingerprint());

        certificate = adapter.getCertificate(TestKeys.CEDRIC_FP.toUpperCase());
        assertEquals(TestKeys.CEDRIC_FP, certificate.getFingerprint(), "We can also fetch with uppercase fps");

        Iterator<String> fingerprints = adapter.getFingerprints();
        assertEquals(TestKeys.CEDRIC_FP, fingerprints.next());
        assertFalse(fingerprints.hasNext());
    }

    @Test
    public void testInsertGetTrustRoot()
            throws BadDataException, BadNameException, IOException, InterruptedException {
        assertThrows(NoSuchElementException.class, () -> adapter.getCertificate(SpecialNames.TRUST_ROOT));

        Certificate certificate = adapter.insertCertificateBySpecialName(
                SpecialNames.TRUST_ROOT, TestKeys.getHarryKey(), merger);
        assertNotNull(certificate);
        assertEquals(TestKeys.HARRY_FP, certificate.getFingerprint());

        assertFalse(adapter.getCertificates().hasNext(), "Special-named certs are not returned by getCertificates()");
        assertFalse(adapter.getFingerprints().hasNext());
    }

    @Test
    public void testGetCertificateIfChanged()
            throws BadDataException, IOException, InterruptedException, BadNameException {
        Certificate certificate = adapter.insertCertificate(TestKeys.getRonCert(), merger);
        Long tag = certificate.getTag();

        assertNull(adapter.getCertificateIfChanged(TestKeys.RON_FP, tag), "Cert has not changed, tag is still valid");
        assertNotNull(adapter.getCertificateIfChanged(TestKeys.RON_FP, tag + 1));
    }

    @Test
    public void testGetTrustRootIfChanged()
            throws BadDataException, BadNameException, IOException, InterruptedException {
        Certificate certificate = adapter.insertCertificateBySpecialName(SpecialNames.TRUST_ROOT, TestKeys.getHarryKey(), merger);
        Long tag = certificate.getTag();

        assertNull(adapter.getCertificateIfChanged(SpecialNames.TRUST_ROOT, tag));
        assertNotNull(adapter.getCertificateIfChanged(SpecialNames.TRUST_ROOT, tag * 2));
    }

    @Test
    public void testGetCertificateBySubkeyId()
            throws BadDataException, IOException, InterruptedException {
        // Insert some certs
        adapter.insertCertificate(TestKeys.getCedricCert(), merger);
        adapter.insertCertificate(TestKeys.getHarryKey(), merger);
        // Now insert Ron
        Certificate certificate = adapter.insertCertificate(TestKeys.getRonCert(), merger);
        List<Long> subkeyIds = certificate.getSubkeyIds();

        assertFalse(adapter.getCertificatesBySubkeyId(0).hasNext());

        for (Long subkeyId : subkeyIds) {
            Iterator<Certificate> certsWithSubkey = adapter.getCertificatesBySubkeyId(subkeyId);
            Certificate certWithSubkey = certsWithSubkey.next();
            assertFalse(certsWithSubkey.hasNext());

            assertEquals(TestKeys.RON_FP, certWithSubkey.getFingerprint());
        }
    }
}
