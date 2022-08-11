// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.cert_d.backend.FileBasedCertificateDirectoryBackend;
import pgp.cert_d.backend.InMemoryCertificateDirectoryBackend;
import pgp.cert_d.exception.NotAStoreException;
import pgp.certificate.KeyMaterialReaderBackend;

import java.io.File;

public final class PGPCertificateDirectories {

    private PGPCertificateDirectories() {

    }

    public static PGPCertificateDirectory inMemoryCertificateDirectory(KeyMaterialReaderBackend keyReader) {
        return new PGPCertificateDirectory(new InMemoryCertificateDirectoryBackend(keyReader));
    }

    public static PGPCertificateDirectory defaultFileBasedCertificateDirectory(KeyMaterialReaderBackend keyReader)
            throws NotAStoreException {
        return fileBasedCertificateDirectory(keyReader, BaseDirectoryProvider.getDefaultBaseDir());
    }

    public static PGPCertificateDirectory fileBasedCertificateDirectory(
            KeyMaterialReaderBackend keyReader, File baseDirectory)
            throws NotAStoreException {
        return new PGPCertificateDirectory(
                new FileBasedCertificateDirectoryBackend(baseDirectory, keyReader));
    }
}
