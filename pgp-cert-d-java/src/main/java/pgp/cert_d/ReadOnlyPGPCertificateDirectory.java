// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.util.Iterator;

/**
 * Interface for a read-only OpenPGP certificate directory.
 */
public interface ReadOnlyPGPCertificateDirectory {

    /**
     * Get the trust-root certificate. This is a certificate which is stored under the special name
     * <pre>trust-root</pre>.
     * If no such certificate is found, <pre>null</pre> is returned.
     *
     * @return trust-root certificate
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the certificate contains bad data
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
     * @return changed certificate, or null if the certificate is unchanged or not found.
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the certificate contains bad data
     */
    Certificate getTrustRootCertificateIfChanged(long tag)
            throws IOException, BadDataException;

    /**
     * Get the certificate identified by the given fingerprint.
     * If no such certificate is found, return <pre>null</pre>.
     *
     * @param fingerprint lower-case fingerprint of the certificate
     * @return certificate or null if no such certificate has been found
     *
     * @throws IOException in case of an IO error
     * @throws BadNameException if the fingerprint is malformed
     * @throws BadDataException if the certificate contains bad data
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
     * @return certificate or null if the certificate has not been changed or has not been found
     *
     * @throws IOException in case of an IO error
     * @throws BadNameException if the fingerprint is malformed
     * @throws BadDataException if the certificate contains bad data
     */
    Certificate getByFingerprintIfChanged(String fingerprint, long tag)
            throws IOException, BadNameException, BadDataException;

    /**
     * Get the certificate identified by the given special name.
     * If no such certificate is found, <pre>null</pre> is returned.
     *
     * @param specialName special name
     * @return certificate or null
     *
     * @throws IOException in case of an IO error
     * @throws BadNameException if the special name is not known
     * @throws BadDataException if the certificate contains bad data
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
