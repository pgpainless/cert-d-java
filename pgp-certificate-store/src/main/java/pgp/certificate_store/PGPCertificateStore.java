// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Interface for an OpenPGP certificate (public key) store.
 */
public interface PGPCertificateStore {

    /**
     * Return the certificate that matches the given identifier.
     *
     * @param identifier identifier for a certificate.
     * @return certificate or null
     *
     * @throws IOException in case of an IO-error
     * @throws BadNameException if the identifier is invalid
     * @throws BadDataException if the certificate file contains invalid data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getCertificate(String identifier)
            throws IOException, BadNameException, BadDataException;

    /**
     * Return the certificate that matches the given identifier, but only if it has been changed.
     * Whether it has been changed is determined by calculating the tag in the directory
     * (e.g. by looking at the inode and last modification date) and comparing the result with the tag provided by
     * the caller.
     *
     * @param identifier certificate identifier
     * @param tag tag by the caller
     * @return certificate if it has been changed, null otherwise
     *
     * @throws IOException in case of an IO-error
     * @throws BadNameException if the identifier is invalid
     * @throws BadDataException if the certificate file contains invalid data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getCertificateIfChanged(String identifier, Long tag)
            throws IOException, BadNameException, BadDataException;

    /**
     * Return an {@link Iterator} over all certificates in the store that contain a subkey with the given
     * subkey id.
     * @param subkeyId id of the subkey
     * @return iterator
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if any of the certificate files contains invalid data
     */
    Iterator<Certificate> getCertificatesBySubkeyId(long subkeyId)
            throws IOException, BadDataException;

    /**
     * Insert a certificate into the store.
     * If an instance of the certificate is already present in the store, the given {@link KeyMaterialMerger} will be
     * used to merge both the existing and the new instance of the {@link Certificate}. The resulting merged certificate
     * will be stored in the store and returned.
     *
     * This method will block until a write-lock on the store can be acquired.
     *
     * @param data input stream containing the new certificate instance
     * @param merge callback for merging with an existing certificate instance
     * @return merged certificate
     *
     * @throws IOException in case of an IO-error
     * @throws InterruptedException in case the inserting thread gets interrupted
     * @throws BadDataException if the data stream does not contain valid OpenPGP data
     */
    Certificate insertCertificate(InputStream data, KeyMaterialMerger merge)
            throws IOException, InterruptedException, BadDataException;

    /**
     * Insert a certificate into the store.
     * The certificate will be stored under the given special name instead of its fingerprint.
     *
     * If an instance of the certificate is already present under the special name in the store, the given {@link KeyMaterialMerger} will be
     * used to merge both the existing and the new instance of the {@link Certificate}. The resulting merged certificate
     * will be stored in the store and returned.
     *
     * This method will block until a write-lock on the store can be acquired.
     *
     * @param specialName special name of the certificate
     * @param data input stream containing the new certificate instance
     * @param merge callback for merging with an existing certificate instance
     * @return merged certificate or null if the store cannot be locked
     *
     * @throws IOException in case of an IO-error
     * @throws InterruptedException if the thread is interrupted
     * @throws BadDataException if the certificate file does not contain valid OpenPGP data
     * @throws BadNameException if the special name is unknown
     */
    Certificate insertCertificateBySpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, InterruptedException, BadDataException, BadNameException;

    /**
     * Return an {@link Iterator} containing all certificates in the store.
     * The iterator will contain both certificates addressed by special names and by fingerprints.
     *
     * @return certificates
     */
    Iterator<Certificate> getCertificates();

    /**
     * Return an {@link Iterator} containing all certificate fingerprints from the store.
     * Note that this only includes the fingerprints of certificate primary keys, not those of subkeys.
     *
     * @return fingerprints
     */
    Iterator<String> getFingerprints();
}
