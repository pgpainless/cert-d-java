// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.PGPCertificateStore;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Adapter class to adapt a {@link PGPCertificateDirectory} to the {@link  PGPCertificateStore} interface.
 */
public class PGPCertificateStoreAdapter implements PGPCertificateStore {

    private final PGPCertificateDirectory directory;

    public PGPCertificateStoreAdapter(PGPCertificateDirectory directory) {
        this.directory = directory;
    }

    @Override
    public Certificate getCertificate(String identifier)
            throws IOException, BadNameException, BadDataException {
        if (SpecialNames.lookupSpecialName(identifier) != null) {
            return directory.getBySpecialName(identifier);
        } else {
            return directory.getByFingerprint(identifier.toLowerCase());
        }
    }

    @Override
    public Iterator<Certificate> getCertificatesBySubkeyId(long subkeyId)
            throws IOException, BadDataException {
        Set<String> fingerprints = directory.getCertificateFingerprintsForSubkeyId(subkeyId);
        Set<Certificate> certificates = new HashSet<>();
        for (String fingerprint : fingerprints) {
            try {
                certificates.add(directory.getByFingerprint(fingerprint));
            } catch (BadNameException e) {
                throw new RuntimeException(e);
            }
        }
        return certificates.iterator();
    }

    @Override
    public Certificate insertCertificate(InputStream data, KeyMaterialMerger merge)
            throws IOException, InterruptedException, BadDataException {
        Certificate certificate = directory.insert(data, merge);
        return certificate;
    }

    @Override
    public Certificate insertCertificateBySpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, InterruptedException, BadDataException, BadNameException {
        return directory.insertWithSpecialName(specialName, data, merge);
    }

    @Override
    public Iterator<Certificate> getCertificates() {
        return directory.items();
    }

    @Override
    public Iterator<String> getFingerprints() {
        return directory.fingerprints();
    }
}
