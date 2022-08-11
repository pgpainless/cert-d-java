// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.certificate.Certificate;

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
