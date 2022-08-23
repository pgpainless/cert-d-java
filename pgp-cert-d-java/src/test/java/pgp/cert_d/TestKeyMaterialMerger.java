// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;

import java.io.IOException;

public class TestKeyMaterialMerger implements KeyMaterialMerger {
    @Override
    public KeyMaterial merge(KeyMaterial data, KeyMaterial existing) throws IOException {
        return data;
    }
}
