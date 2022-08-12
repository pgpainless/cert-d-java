// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.certificate;

import java.io.IOException;
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

    Certificate asCertificate();

    /**
     * Return an {@link InputStream} of the binary representation of the secret key.
     *
     * @return input stream
     * @throws IOException in case of an IO error
     */
    InputStream getInputStream() throws IOException;

    String getTag() throws IOException;

    /**
     * Return a {@link Set} containing key-ids of subkeys.
     *
     * @return subkeys
     * @throws IOException in case of an IO error
     */
    List<Long> getSubkeyIds() throws IOException;
}
