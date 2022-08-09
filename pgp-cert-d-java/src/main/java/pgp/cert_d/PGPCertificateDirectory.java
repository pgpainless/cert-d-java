// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.Certificate;
import pgp.certificate_store.KeyMaterial;
import pgp.certificate_store.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class PGPCertificateDirectory
        implements ReadOnlyPGPCertificateDirectory, WritingPGPCertificateDirectory {

    private final Backend backend;

    public PGPCertificateDirectory(Backend backend) {
        this.backend = backend;
    }

    @Override
    public Certificate getByFingerprint(String fingerprint) throws BadDataException, BadNameException, IOException {
        return backend.readByFingerprint(fingerprint);
    }

    @Override
    public Certificate getBySpecialName(String specialName)
            throws BadNameException, BadDataException, IOException {
        KeyMaterial keyMaterial = backend.readBySpecialName(specialName);
        if (keyMaterial != null) {
            return keyMaterial.asCertificate();
        }
        return null;
    }

    @Override
    public Certificate getTrustRootCertificate()
            throws IOException, BadDataException {
        try {
            return getBySpecialName(SpecialNames.TRUST_ROOT);
        } catch (BadNameException e) {
            throw new AssertionError("'" + SpecialNames.TRUST_ROOT + "' is an implementation MUST");
        }
    }

    @Override
    public Iterator<Certificate> items() {
        return backend.readItems();
    }

    @Override
    public Iterator<String> fingerprints() {
        Iterator<Certificate> certs = items();
        return new Iterator<String>() {
            @Override
            public boolean hasNext() {
                return certs.hasNext();
            }

            @Override
            public String next() {
                return certs.next().getFingerprint();
            }
        };
    }

    @Override
    public KeyMaterial getTrustRoot() throws IOException, BadDataException {
        try {
            return backend.readBySpecialName(SpecialNames.TRUST_ROOT);
        } catch (BadNameException e) {
            throw new AssertionError("'" + SpecialNames.TRUST_ROOT + "' is implementation MUST");
        }
    }

    @Override
    public KeyMaterial insertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, InterruptedException {
        backend.getLock().lockDirectory();
        KeyMaterial inserted = backend.doInsertTrustRoot(data, merge);
        backend.getLock().releaseDirectory();
        return inserted;
    }

    @Override
    public KeyMaterial tryInsertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException {
        if (!backend.getLock().tryLockDirectory()) {
            return null;
        }
        KeyMaterial inserted = backend.doInsertTrustRoot(data, merge);
        backend.getLock().releaseDirectory();
        return inserted;
    }



    @Override
    public Certificate insert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, InterruptedException {
        backend.getLock().lockDirectory();
        Certificate inserted = backend.doInsert(data, merge);
        backend.getLock().releaseDirectory();
        return inserted;
    }

    @Override
    public Certificate tryInsert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException {
        if (!backend.getLock().tryLockDirectory()) {
            return null;
        }
        Certificate inserted = backend.doInsert(data, merge);
        backend.getLock().releaseDirectory();
        return inserted;
    }

    @Override
    public Certificate insertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException, InterruptedException {
        backend.getLock().lockDirectory();
        Certificate inserted = backend.doInsertWithSpecialName(specialName, data, merge);
        backend.getLock().releaseDirectory();
        return inserted;
    }

    @Override
    public Certificate tryInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException {
        if (!backend.getLock().tryLockDirectory()) {
            return null;
        }
        Certificate inserted = backend.doInsertWithSpecialName(specialName, data, merge);
        backend.getLock().releaseDirectory();
        return inserted;
    }

    public interface Backend {

        LockingMechanism getLock();

        Certificate readByFingerprint(String fingerprint) throws BadNameException, IOException, BadDataException;

        KeyMaterial readBySpecialName(String specialName) throws BadNameException, IOException, BadDataException;

        Iterator<Certificate> readItems();

        KeyMaterial doInsertTrustRoot(InputStream data, KeyMaterialMerger merge)
                throws BadDataException, IOException;

        Certificate doInsert(InputStream data, KeyMaterialMerger merge)
                        throws IOException, BadDataException;

        Certificate doInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
                                throws IOException, BadDataException, BadNameException;
    }

    public interface LockingMechanism {

        /**
         * Lock the store for writes.
         * Readers can continue to use the store and will always see consistent certs.
         *
         * @throws IOException in case of an IO error
         * @throws InterruptedException if the thread gets interrupted
         */
        void lockDirectory() throws IOException, InterruptedException;

        /**
         * Try top lock the store for writes.
         * Return false without locking the store in case the store was already locked.
         *
         * @return true if locking succeeded, false otherwise
         *
         * @throws IOException in case of an IO error
         */
        boolean tryLockDirectory() throws IOException;

        boolean isLocked();

        /**
         * Release the directory write-lock acquired via {@link #lockDirectory()}.
         *
         * @throws IOException in case of an IO error
         */
        void releaseDirectory() throws IOException;

    }
}
