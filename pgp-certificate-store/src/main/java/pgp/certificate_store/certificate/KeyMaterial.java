// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.certificate;

import java.io.InputStream;
import java.util.List;
import java.util.Set;

public interface KeyMaterial {

    /**
     * Return the fingerprint of the certificate as 40 lowercase hex characters.
     * TODO: Allow OpenPGP V5 fingerprints
     *
     * @return fingerprint
     */
    String getFingerprint();

    /**
     * Return the {@link Certificate} belonging to this key material.
     * If this is already a {@link Certificate}, return this.
     * If this is a {@link Key}, extract the {@link Certificate} and return it.
     *
     * @return certificate
     */
    Certificate asCertificate();

    /**
     * Return an {@link InputStream} of the binary representation of the secret key.
     *
     * @return input stream
     */
    InputStream getInputStream();

    /**
     * Return the tag belonging to this key material.
     * The tag can be used to keep an application cache in sync with what is in the directory.
     *
     * @return tag
     */
    Long getTag();

    /**
     * Return a {@link Set} containing key-ids of subkeys.
     *
     * @return subkeys
     */
    List<Long> getSubkeyIds();
}
