// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

/**
 * OpenPGP certificate (public key).
 */
public abstract class Certificate implements KeyMaterial {

    /**
     * Return an {@link InputStream} of the binary representation of the certificate.
     *
     * @return input stream
     * @throws IOException in case of an IO error
     */
    public abstract InputStream getInputStream() throws IOException;

    /**
     * Return a tag of the certificate.
     * The tag is a checksum calculated over the binary representation of the certificate.
     *
     * @return tag
     * @throws IOException in case of an IO error
     */
    public abstract String getTag() throws IOException;

    /**
     * Return a {@link Set} containing key-ids of subkeys.
     *
     * @return subkeys
     * @throws IOException in case of an IO error
     */
    public abstract Set<Long> getSubkeyIds() throws IOException;
}
