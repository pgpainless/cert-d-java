// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * Interface for a read-only OpenPGP certificate directory.
 */
public interface ReadOnlyPGPCertificateDirectory {

    /**
     * Get the trust-root certificate. This is a certificate which is stored under the special name
     * <pre>trust-root</pre>.
     *
     * @return trust-root certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the certificate contains bad data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getTrustRootCertificate()
            throws IOException, BadDataException;

    /**
     * Get the trust-root certificate if it has changed.
     * This method uses the <pre>tag</pre> to calculate if the certificate might have changed.
     * If the computed tag equals the given tag, the certificate has not changed, so <pre>null</pre> is returned.
     * Otherwise. the changed certificate is returned.
     *
     * @param tag tag
     * @return changed certificate, or null if the certificate is unchanged.
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the certificate contains bad data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getTrustRootCertificateIfChanged(long tag)
            throws IOException, BadDataException;

    /**
     * Get the certificate identified by the given fingerprint.
     *
     * @param fingerprint lower-case fingerprint of the certificate
     * @return certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadNameException if the fingerprint is malformed
     * @throws BadDataException if the certificate contains bad data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getByFingerprint(String fingerprint)
            throws IOException, BadNameException, BadDataException;

    /**
     * Get the certificate identified by the given fingerprint if it has changed.
     * This method uses the <pre>tag</pre> to calculate, if the certificate might have changed.
     * If the computed tag equals the given tag, the certificate has not changed, so <pre>null</pre> is returned.
     * Otherwise, the changed certificate is returned.
     *
     * @param fingerprint lower-case fingerprint of the certificate
     * @param tag tag
     * @return certificate or null if the certificate has not been changed
     *
     * @throws IOException in case of an IO error
     * @throws BadNameException if the fingerprint is malformed
     * @throws BadDataException if the certificate contains bad data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getByFingerprintIfChanged(String fingerprint, long tag)
            throws IOException, BadNameException, BadDataException;

    /**
     * Get the certificate identified by the given special name.
     *
     * @param specialName special name
     * @return certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadNameException if the special name is not known
     * @throws BadDataException if the certificate contains bad data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getBySpecialName(String specialName)
            throws IOException, BadNameException, BadDataException;

    /**
     * Get the certificate identified by the given special name or null, if it has not been changed.
     * This method uses the <pre>tag</pre> to calculate, if the certificate might have changed.
     * If the computed tag equals the given tag, the certificate has not changed, so <pre>null</pre> is returned.
     * Otherwise, the changed certificate is returned.
     *
     * @param specialName special name
     * @param tag tag
     * @return certificate or null
     *
     * @throws IOException in case of an IO error
     * @throws BadNameException if the special name is not known
     * @throws BadDataException if the certificate contains bad data
     * @throws NoSuchElementException if no such certificate is found
     */
    Certificate getBySpecialNameIfChanged(String specialName, long tag)
            throws IOException, BadNameException, BadDataException;

    /**
     * Get all certificates in the directory, except for certificates which are stored by special name.
     *
     * @return iterator of certificates
     */
    Iterator<Certificate> items();

    /**
     * Get the fingerprints of all certificates in the directory, except for certificates which are stored by
     * special name.
     *
     * @return iterator of fingerprints
     */
    Iterator<String> fingerprints();
}
