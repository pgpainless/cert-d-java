// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

/**
 * Interface definition for a class that can read {@link Certificate Certificates} from binary
 * {@link InputStream InputStreams}.
 */
public interface CertificateReaderBackend {

    /**
     * Read a {@link Certificate} from the given {@link InputStream}.
     *
     * @param inputStream input stream containing the binary representation of the certificate.
     * @return certificate object
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException in case that the input stream does not contain OpenPGP certificate data
     */
    Certificate readCertificate(InputStream inputStream) throws IOException, BadDataException;

}
