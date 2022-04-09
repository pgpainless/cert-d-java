// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

public abstract class Certificate {
    /**
     * Return the fingerprint of the certificate as lowercase hex characters.
     * OpenPGP v4 fingerprints consist of 40 characters, while OpenPGP v5 fingerprints consist of 64.
     *
     * @return fingerprint
     */
    public abstract String getFingerprint();

    /**
     * Return an {@link InputStream} of the binary representation of the certificate.
     *
     * @return input stream
     */
    public abstract InputStream getInputStream() throws IOException;

    /**
     * Return a tag of the certificate.
     * The tag is a checksum calculated over the binary representation of the certificate.
     *
     * @return tag
     */
    public abstract String getTag() throws IOException;

    public abstract Set<Long> getSubkeyIds() throws IOException;
}
