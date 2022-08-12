// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.certificate;

import java.io.IOException;

/**
 * Merge a given {@link Key} (update) with an existing {@link Key}.
 */
public interface KeyMaterialMerger {

    /**
     * Merge the given key material with an existing copy and return the result.
     * If no existing {@link KeyMaterial} is found (i.e. if existing is null), this method returns the unmodified data.
     *
     * @param data key material
     * @param existing optional already existing copy of the key material
     * @return merged key material
     *
     * @throws IOException in case of an IO error
     */
    KeyMaterial merge(KeyMaterial data, KeyMaterial existing) throws IOException;
}
