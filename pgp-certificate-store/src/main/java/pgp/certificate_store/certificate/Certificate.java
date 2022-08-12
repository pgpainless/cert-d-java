// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.certificate;

/**
 * OpenPGP certificate (public key).
 */
public abstract class Certificate implements KeyMaterial {

    @Override
    public Certificate asCertificate() {
        return this;
    }
}
