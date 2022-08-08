// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.CertificateMerger;
import pgp.certificate_store.KeyReaderBackend;

public abstract class BackendProvider {

    public abstract KeyReaderBackend provideKeyReaderBackend();

    public abstract CertificateMerger provideDefaultMergeCallback();

}
