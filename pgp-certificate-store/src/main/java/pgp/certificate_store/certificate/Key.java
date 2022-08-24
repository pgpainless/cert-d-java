// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.certificate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;

/**
 * OpenPGP key (secret key).
 */
public class Key implements KeyMaterial {

    private final byte[] bytes;
    private final Certificate certificate;
    private final Long tag;

    /**
     * Key constructor.
     *
     * @param bytes encoding of the key
     * @param certificate associated certificate
     * @param tag tag
     */
    public Key(byte[] bytes, Certificate certificate, Long tag) {
        this.bytes = bytes;
        this.certificate = certificate;
        this.tag = tag;
    }

    /**
     * Copy constructor to change the tag of both the {@link Key} and its {@link Certificate}.
     *
     * @param key key
     * @param tag tag
     */
    public Key(Key key, Long tag) {
        this(key.bytes, new Certificate(key.certificate, tag), tag);
    }

    /**
     * Return the certificate part of this OpenPGP key.
     *
     * @return OpenPGP certificate
     */
    public Certificate getCertificate() {
        return new Certificate(certificate, getTag());
    }

    @Override
    public String getFingerprint() {
        return certificate.getFingerprint();
    }

    @Override
    public Certificate asCertificate() {
        return getCertificate();
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
        return certificate.getSubkeyIds();
    }

}
