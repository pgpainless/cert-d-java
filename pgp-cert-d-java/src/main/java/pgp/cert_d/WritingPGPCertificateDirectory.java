// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;

/**
 * Interface for a writing OpenPGP certificate directory.
 */
public interface WritingPGPCertificateDirectory {

    /**
     * Return the certificate or key identified by the special name <pre>trust-root</pre>.
     *
     * @return trust-root key or certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the certificate contains bad data
     */
    KeyMaterial getTrustRoot()
            throws IOException, BadDataException;

    /**
     * Insert a key or certificate under the special name <pre>trust-root</pre>.
     * This method blocks until the key material has been written.
     *
     * @param data input stream containing the key or certificate
     * @param merge key material merger to merge the key or certificate with existing key material
     * @return the merged or inserted key or certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the data stream or the existing trust-root key material contains bad data
     * @throws InterruptedException if the thread is interrupted
     */
    KeyMaterial insertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, InterruptedException;

    /**
     * Insert a key or certificate under the special name <pre>trust-root</pre>.
     * Contrary to {@link #insertTrustRoot(InputStream, KeyMaterialMerger)}, this method does not block.
     * Instead, it returns null if the write-lock cannot be obtained.
     *
     * @param data input stream containing the key or certificate
     * @param merge key material merger to merge the key or certificate with existing key material
     * @return the merged or inserted key or certificate, or null if the write-lock cannot be obtained
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the thread is interrupted
     */
    KeyMaterial tryInsertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException;

    /**
     * Insert a certificate identified by its fingerprint.
     * This method blocks until the certificate has been written.
     *
     * @param data input stream containing the certificate data
     * @param merge merge callback to merge the certificate with existing certificate material
     * @return the merged or inserted certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the data stream or existing certificate contains bad data
     * @throws InterruptedException if the thread is interrupted
     */
    Certificate insert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, InterruptedException;

    /**
     * Insert a certificate identified by its fingerprint.
     * Contrary to {@link #insert(InputStream, KeyMaterialMerger)}, this method does not block.
     * Instead, it returns null if the write-lock cannot be obtained.
     *
     * @param data input stream containing the certificate data
     * @param merge merge callback to  merge the certificate with existing certificate material
     * @return the merged or inserted certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the data stream or existing certificate contains bad data
     */
    Certificate tryInsert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException;

    /**
     * Insert a certificate or key under the given special name.
     * This method blocks until the certificate/key has been written.
     *
     * @param specialName special name under which the key material shall be inserted
     * @param data input stream containing the key/certificate data
     * @param merge callback to merge the key/certificate with existing key material
     * @return certificate component of the merged or inserted key material data
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the data stream or the existing certificate contains bad data
     * @throws BadNameException if the special name is not known
     * @throws InterruptedException if the thread is interrupted
     */
    Certificate insertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException, InterruptedException;

    /**
     * Insert a certificate or key under the given special name.
     * Contrary to {@link #insertWithSpecialName(String, InputStream, KeyMaterialMerger)}, this method does not block.
     * Instead, it returns null if the write-lock cannot be obtained.
     *
     * @param specialName special name under which the key material shall be inserted
     * @param data input stream containing the key material
     * @param merge callback to merge the key/certificate with existing key material
     * @return certificate component of the merged or inserted key material
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the data stream or existing key material contains bad data
     * @throws BadNameException if the special name is not known
     */
    Certificate tryInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException;

}
