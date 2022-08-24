// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.certificate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;

/**
 * OpenPGP certificate (public key).
 */
public class Certificate implements KeyMaterial {

    private final byte[] bytes;
    private final String fingerprint;
    private final List<Long> subkeyIds;
    private final Long tag;

    /**
     * Certificate constructor.
     *
     * @param bytes encoding of the certificate
     * @param fingerprint fingerprint (lowercase hex characters)
     * @param subkeyIds list of subkey ids
     * @param tag tag
     */
    public Certificate(byte[] bytes, String fingerprint, List<Long> subkeyIds, Long tag) {
        this.bytes = bytes;
        this.fingerprint = fingerprint;
        this.subkeyIds = subkeyIds;
        this.tag = tag;
    }

    /**
     * Copy constructor to assign a new tag to the {@link Certificate}.
     *
     * @param cert certificate
     * @param tag tag
     */
    public Certificate(Certificate cert, Long tag) {
        this(cert.bytes, cert.fingerprint, cert.subkeyIds, tag);
    }

    @Override
    public String getFingerprint() {
        return fingerprint;
    }

    @Override
    public Certificate asCertificate() {
        return this;
    }

    @Override
    public InputStream getInputStream() {
        return new ByteArrayInputStream(bytes);
    }

    @Override
    public Long getTag() {
        return tag;
    }

    @Override
    public List<Long> getSubkeyIds() {
        return subkeyIds;
    }
}
