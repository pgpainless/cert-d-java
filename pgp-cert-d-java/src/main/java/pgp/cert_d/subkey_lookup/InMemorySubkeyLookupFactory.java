// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.subkey_lookup;

import java.io.File;

public class InMemorySubkeyLookupFactory implements SubkeyLookupFactory {
    @Override
    public SubkeyLookup createFileBasedInstance(File baseDirectory) {
        return new InMemorySubkeyLookup();
    }
}
