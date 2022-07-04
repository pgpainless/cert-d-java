// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

public interface KeyReaderBackend {

    /**
     * Read a {@link Key} from the given {@link InputStream}.
     *
     * @param data input stream containing the binary representation of the key.
     * @return key object
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException in case that the data stream does not contain a valid OpenPGP key
     */
    Key readKey(InputStream data) throws IOException, BadDataException;
}
