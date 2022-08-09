// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.Certificate;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.util.Iterator;

public interface ReadOnlyPGPCertificateDirectory {

    Certificate getTrustRootCertificate()
            throws IOException, BadDataException;

    Certificate getByFingerprint(String fingerprint)
            throws IOException, BadNameException, BadDataException;

    Certificate getBySpecialName(String specialName)
            throws IOException, BadNameException, BadDataException;

    Iterator<Certificate> items();

    Iterator<String> fingerprints();
}