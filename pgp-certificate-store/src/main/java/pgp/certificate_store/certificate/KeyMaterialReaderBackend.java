// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.certificate;

import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

public interface KeyMaterialReaderBackend {

    /**
     * Read a {@link KeyMaterial} (either {@link Key} or {@link Certificate}) from the given {@link InputStream}.
     *
     * @param data input stream containing the binary representation of the key.
     * @return key or certificate object
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException in case that the data stream does not contain a valid OpenPGP key/certificate
     */
    KeyMaterial read(InputStream data, Long tag) throws IOException, BadDataException;
}
