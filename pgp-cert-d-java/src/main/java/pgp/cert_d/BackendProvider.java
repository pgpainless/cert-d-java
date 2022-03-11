// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.CertificateMerger;
import pgp.CertificateReader;

public abstract class BackendProvider {

    public abstract CertificateReader provideCertificateReaderBackend();

    public abstract CertificateMerger provideDefaultMergeCallback();

}
