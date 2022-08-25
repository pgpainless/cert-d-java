// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.backend;

import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.SpecialNames;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.Key;
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
import java.util.concurrent.atomic.AtomicLong;

/**
 * Implementation of the {@link PGPCertificateDirectory.Backend} which stores key material in-memory.
 * It uses object locking with {@link #wait()} and {@link #notify()} to synchronize write-access.
 */
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
    private final AtomicLong nonce = new AtomicLong(1);

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
    public KeyMaterial readBySpecialName(String specialName) throws BadNameException {
        if (SpecialNames.lookupSpecialName(specialName) == null) {
            throw new BadNameException("Invalid special name " + specialName);
        }
        return keyMaterialSpecialNameMap.get(specialName);
    }

    @Override
    public Iterator<Certificate> readItems() {
        return certificateFingerprintMap.values().iterator();
    }

    @Override
    public KeyMaterial doInsertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws BadDataException, IOException {
        KeyMaterial update = reader.read(data, null);
        KeyMaterial existing = null;
        try {
            existing = readBySpecialName(SpecialNames.TRUST_ROOT);
        } catch (BadNameException e) {
            // Does not happen
            throw new RuntimeException(e);
        }
        KeyMaterial merged = merge.merge(update, existing);
        if (merged instanceof Key) {
            merged = new Key((Key) merged, newTag());
        } else {
            merged = new Certificate((Certificate) merged, newTag());
        }
        keyMaterialSpecialNameMap.put(SpecialNames.TRUST_ROOT, merged);
        return merged;
    }


    @Override
    public Certificate doInsert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException {
        KeyMaterial update = reader.read(data, null);
        Certificate existing = readByFingerprint(update.getFingerprint());
        Certificate merged = merge.merge(update, existing).asCertificate();
        merged = new Certificate(merged, newTag());
        certificateFingerprintMap.put(update.getFingerprint(), merged);
        return merged;
    }

    @Override
    public Certificate doInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException {
        KeyMaterial keyMaterial = reader.read(data, null);
        KeyMaterial existing = readBySpecialName(specialName);
        KeyMaterial merged = merge.merge(keyMaterial, existing);
        if (merged instanceof Key) {
            merged = new Key((Key) merged, newTag());
        } else {
            merged = new Certificate((Certificate) merged, newTag());
        }
        keyMaterialSpecialNameMap.put(specialName, merged);
        return merged.asCertificate();
    }

    @Override
    public Long getTagForFingerprint(String fingerprint) throws BadNameException, IOException {
        Certificate certificate = certificateFingerprintMap.get(fingerprint);
        if (certificate == null) {
            return null;
        }
        return certificate.getTag();
    }

    @Override
    public Long getTagForSpecialName(String specialName) throws BadNameException, IOException {
        if (SpecialNames.lookupSpecialName(specialName) == null) {
            throw new BadNameException("Invalid special name " + specialName);
        }
        KeyMaterial tagged = keyMaterialSpecialNameMap.get(specialName);
        if (tagged == null) {
            return null;
        }
        return tagged.getTag();
    }

    private Long newTag() {
        return System.currentTimeMillis() + nonce.incrementAndGet();
    }
}
