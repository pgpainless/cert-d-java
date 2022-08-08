// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

public interface KeyMaterial {

    /**
     * Return the fingerprint of the certificate as 40 lowercase hex characters.
     * TODO: Allow OpenPGP V5 fingerprints
     *
     * @return fingerprint
     */
    String getFingerprint();

}
