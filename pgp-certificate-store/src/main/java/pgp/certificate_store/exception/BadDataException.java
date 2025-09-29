// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.exception;

/**
 * The data was not a valid OpenPGP cert or key in binary format.
 */
public class BadDataException extends Exception {

    @Deprecated // pass cause and/or message
    public BadDataException() {
        super();
    }

    public BadDataException(Throwable cause) {
        super(cause);
    }

    public BadDataException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadDataException(String message) {
        super(message);
    }
}
