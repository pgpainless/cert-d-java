// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.subkey_lookup;

import java.io.File;

public interface SubkeyLookupFactory {

    /**
     * Create a new {@link SubkeyLookup} instance that lives in the given baseDirectory.
     *
     * @param baseDirectory base directory
     * @return subkey lookup
     */
    SubkeyLookup createFileBasedInstance(File baseDirectory);
}
