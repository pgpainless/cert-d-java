// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;

/**
 * Merge a given {@link Key} (update) with an existing {@link Key}.
 */
public interface KeyMerger {

    /**
     * Merge the given key data with the existing {@link Key} and return the result.
     * If no existing {@link Key} is found (i.e. if existing is null), this method returns the unmodified data.
     *
     * @param data key
     * @param existing optional already existing copy of the key
     * @return merged key
     *
     * @throws IOException in case of an IO error
     */
    Key merge(Key data, Key existing) throws IOException;
}
