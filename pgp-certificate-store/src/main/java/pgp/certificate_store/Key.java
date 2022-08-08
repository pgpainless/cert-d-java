// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;
import java.io.InputStream;

/**
 * OpenPGP key (secret key).
 */
public abstract class Key implements KeyMaterial {

    /**
     * Return the certificate part of this OpenPGP key.
     *
     * @return OpenPGP certificate
     */
    public abstract Certificate getCertificate();

    /**
     * Return an {@link InputStream} of the binary representation of the secret key.
     *
     * @return input stream
     * @throws IOException in case of an IO error
     */
    public abstract InputStream getInputStream() throws IOException;

    public abstract String getTag() throws IOException;

}
