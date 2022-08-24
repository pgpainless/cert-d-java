// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Implementation of the Shared PGP Certificate Directory.
 *
 * @see <a href="https://sequoia-pgp.gitlab.io/pgp-cert-d/">Shared PGP Certificate Directory Specification</a>
 */
public class PGPCertificateDirectory
        implements ReadOnlyPGPCertificateDirectory, WritingPGPCertificateDirectory, SubkeyLookup {

    final Backend backend;
    final SubkeyLookup subkeyLookup;
    private final Pattern openPgpV4FingerprintPattern = Pattern.compile("^[a-f0-9]{40}$");

    /**
     * Constructor for a PGP certificate directory.
     *
     * @param backend storage backend
     * @param subkeyLookup subkey lookup mechanism to map subkey-ids to certificates
     */
    public PGPCertificateDirectory(Backend backend, SubkeyLookup subkeyLookup) {
        this.backend = backend;
        this.subkeyLookup = subkeyLookup;
    }

    @Override
    public Certificate getByFingerprint(String fingerprint) throws BadDataException, BadNameException, IOException {
        if (!openPgpV4FingerprintPattern.matcher(fingerprint).matches()) {
            throw new BadNameException();
        }
        return backend.readByFingerprint(fingerprint);
    }

    @Override
    public Certificate getByFingerprintIfChanged(String fingerprint, long tag)
            throws IOException, BadNameException, BadDataException {
        if (tag != backend.getTagForFingerprint(fingerprint)) {
            return getByFingerprint(fingerprint);
        }
        return null;
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
    public Certificate getBySpecialNameIfChanged(String specialName, long tag)
            throws IOException, BadNameException, BadDataException {
        if (tag != backend.getTagForSpecialName(specialName)) {
            return getBySpecialName(specialName);
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
    public Certificate getTrustRootCertificateIfChanged(long tag) throws IOException, BadDataException {
        try {
            return getBySpecialNameIfChanged(SpecialNames.TRUST_ROOT, tag);
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
        subkeyLookup.storeCertificateSubkeyIds(inserted.getFingerprint(), inserted.getSubkeyIds());
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
        subkeyLookup.storeCertificateSubkeyIds(inserted.getFingerprint(), inserted.getSubkeyIds());
        backend.getLock().releaseDirectory();
        return inserted;
    }



    @Override
    public Certificate insert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, InterruptedException {
        backend.getLock().lockDirectory();
        Certificate inserted = backend.doInsert(data, merge);
        subkeyLookup.storeCertificateSubkeyIds(inserted.getFingerprint(), inserted.getSubkeyIds());
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
        subkeyLookup.storeCertificateSubkeyIds(inserted.getFingerprint(), inserted.getSubkeyIds());
        backend.getLock().releaseDirectory();
        return inserted;
    }

    @Override
    public Certificate insertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException, InterruptedException {
        backend.getLock().lockDirectory();
        Certificate inserted = backend.doInsertWithSpecialName(specialName, data, merge);
        subkeyLookup.storeCertificateSubkeyIds(inserted.getFingerprint(), inserted.getSubkeyIds());
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
        subkeyLookup.storeCertificateSubkeyIds(inserted.getFingerprint(), inserted.getSubkeyIds());
        backend.getLock().releaseDirectory();
        return inserted;
    }

    @Override
    public Set<String> getCertificateFingerprintsForSubkeyId(long subkeyId) throws IOException {
        return subkeyLookup.getCertificateFingerprintsForSubkeyId(subkeyId);
    }

    @Override
    public void storeCertificateSubkeyIds(String certificate, List<Long> subkeyIds) throws IOException {
        subkeyLookup.storeCertificateSubkeyIds(certificate, subkeyIds);
    }

    /**
     * Storage backend.
     */
    public interface Backend {

        /**
         * Get the locking mechanism to write-lock the backend.
         *
         * @return lock
         */
        LockingMechanism getLock();

        /**
         * Read a {@link Certificate} by its OpenPGP fingerprint.
         *
         * @param fingerprint fingerprint
         * @return certificate
         *
         * @throws BadNameException if the fingerprint is malformed
         * @throws IOException in case of an IO error
         * @throws BadDataException if the certificate contains bad data
         */
        Certificate readByFingerprint(String fingerprint) throws BadNameException, IOException, BadDataException;

        /**
         * Read a {@link Certificate} or {@link pgp.certificate_store.certificate.Key} by the given special name.
         *
         * @param specialName special name
         * @return certificate or key
         *
         * @throws BadNameException if the special name is not known
         * @throws IOException in case of an IO error
         * @throws BadDataException if the certificate contains bad data
         */
        KeyMaterial readBySpecialName(String specialName) throws BadNameException, IOException, BadDataException;

        /**
         * Return an {@link Iterator} of all {@link Certificate Certificates} in the store, except for certificates
         * stored under a special name.
         *
         * @return iterator
         */
        Iterator<Certificate> readItems();

        /**
         * Insert a {@link pgp.certificate_store.certificate.Key} or {@link Certificate} as trust-root.
         *
         * @param data input stream containing the key material
         * @param merge callback to merge the key material with existing key material
         * @return merged or inserted key material
         *
         * @throws BadDataException if the data stream or existing key material contains bad data
         * @throws IOException in case of an IO error
         */
        KeyMaterial doInsertTrustRoot(InputStream data, KeyMaterialMerger merge)
                throws BadDataException, IOException;

        /**
         * Insert a {@link Certificate} identified by its fingerprint into the directory.
         *
         * @param data input stream containing the certificate data
         * @param merge callback to merge the certificate with existing key material
         * @return merged or inserted certificate
         *
         * @throws IOException in case of an IO error
         * @throws BadDataException if the data stream or existing certificate contains bad data
         */
        Certificate doInsert(InputStream data, KeyMaterialMerger merge)
                        throws IOException, BadDataException;

        /**
         * Insert a {@link pgp.certificate_store.certificate.Key} or {@link Certificate} under the given special name.
         *
         * @param specialName special name to identify the key material with
         * @param data data stream containing the key or certificate
         * @param merge callback to merge the key/certificate with existing key material
         * @return certificate component of the merged or inserted key material
         *
         * @throws IOException in case of an IO error
         * @throws BadDataException if the data stream or existing key material contains bad data
         * @throws BadNameException if the special name is not known
         */
        Certificate doInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
                                throws IOException, BadDataException, BadNameException;

        /**
         * Calculate the tag of the certificate with the given fingerprint.
         *
         * @param fingerprint fingerprint
         * @return tag
         *
         * @throws BadNameException if the fingerprint is malformed
         * @throws IOException in case of an IO error
         * @throws IllegalArgumentException if the certificate does not exist
         */
        Long getTagForFingerprint(String fingerprint) throws BadNameException, IOException;

        /**
         * Calculate the tag of the certificate identified by the given special name.
         *
         * @param specialName special name
         * @return tag
         *
         * @throws BadNameException if the special name is not known
         * @throws IOException in case of an IO error
         * @throws IllegalArgumentException if the certificate or key does not exist
         */
        Long getTagForSpecialName(String specialName) throws BadNameException, IOException;
    }

    /**
     * Interface for a write-locking mechanism.
     */
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

        /**
         * Return true if the lock is in locked state.
         *
         * @return true if locked
         */
        boolean isLocked();

        /**
         * Release the directory write-lock acquired via {@link #lockDirectory()}.
         *
         * @throws IOException in case of an IO error
         */
        void releaseDirectory() throws IOException;

    }
}
