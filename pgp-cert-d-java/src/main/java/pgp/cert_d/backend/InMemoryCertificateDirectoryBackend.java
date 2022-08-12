// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.backend;

import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.SpecialNames;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class InMemoryCertificateDirectoryBackend implements PGPCertificateDirectory.Backend {

    protected static class ObjectLockingMechanism implements PGPCertificateDirectory.LockingMechanism {

        private boolean locked = false;

        @Override
        public synchronized void lockDirectory() throws InterruptedException {
            if (isLocked()) {
                wait();
            }
            locked = true;
        }

        @Override
        public synchronized boolean tryLockDirectory() {
            if (isLocked()) {
                return false;
            }
            locked = true;
            return true;
        }

        @Override
        public synchronized boolean isLocked() {
            return locked;
        }

        @Override
        public synchronized void releaseDirectory() {
            locked = false;
            notify();
        }
    }


    private final Map<String, Certificate> certificateFingerprintMap = new HashMap<>();
    private final Map<String, KeyMaterial> keyMaterialSpecialNameMap = new HashMap<>();
    private final PGPCertificateDirectory.LockingMechanism lock = new ObjectLockingMechanism();
    private final KeyMaterialReaderBackend reader;

    public InMemoryCertificateDirectoryBackend(KeyMaterialReaderBackend reader) {
        this.reader = reader;
    }

    @Override
    public PGPCertificateDirectory.LockingMechanism getLock() {
        return lock;
    }

    @Override
    public Certificate readByFingerprint(String fingerprint) {
        return certificateFingerprintMap.get(fingerprint);
    }


    @Override
    public KeyMaterial readBySpecialName(String specialName) {
        return keyMaterialSpecialNameMap.get(specialName);
    }

    @Override
    public Iterator<Certificate> readItems() {
        return certificateFingerprintMap.values().iterator();
    }

    @Override
    public KeyMaterial doInsertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws BadDataException, IOException {
        KeyMaterial update = reader.read(data);
        KeyMaterial existing = readBySpecialName(SpecialNames.TRUST_ROOT);
        KeyMaterial merged = merge.merge(update, existing);
        keyMaterialSpecialNameMap.put(SpecialNames.TRUST_ROOT, merged);
        return merged;
    }


    @Override
    public Certificate doInsert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException {
        KeyMaterial update = reader.read(data);
        Certificate existing = readByFingerprint(update.getFingerprint());
        Certificate merged = merge.merge(update, existing).asCertificate();
        certificateFingerprintMap.put(update.getFingerprint(), merged);
        return merged;
    }

    @Override
    public Certificate doInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException {
        KeyMaterial keyMaterial = reader.read(data);
        KeyMaterial existing = readBySpecialName(specialName);
        KeyMaterial merged = merge.merge(keyMaterial, existing);
        keyMaterialSpecialNameMap.put(specialName, merged);
        return merged.asCertificate();
    }
}
