// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.exception;

/**
 * Thrown when a bad name for a cert was used.
 */
public class BadNameException extends Exception {

    public BadNameException() {
        super();
    }

    public BadNameException(String message) {
        super(message);
    }
}
