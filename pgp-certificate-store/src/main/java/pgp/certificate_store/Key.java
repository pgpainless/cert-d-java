// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

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

    @Override
    public Certificate asCertificate() {
        return getCertificate();
    }

}
