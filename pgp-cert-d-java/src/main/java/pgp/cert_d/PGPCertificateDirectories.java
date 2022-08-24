// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.cert_d.backend.FileBasedCertificateDirectoryBackend;
import pgp.cert_d.backend.InMemoryCertificateDirectoryBackend;
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookup;
import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.NotAStoreException;

import java.io.File;

/**
 * Static factory methods that return implementations of the {@link PGPCertificateDirectory} class.
 */
public final class PGPCertificateDirectories {

    private PGPCertificateDirectories() {

    }

    public static PGPCertificateDirectory inMemoryCertificateDirectory(
            KeyMaterialReaderBackend keyReader) {
        return new PGPCertificateDirectory(
                new InMemoryCertificateDirectoryBackend(keyReader), new InMemorySubkeyLookup());
    }

    public static PGPCertificateDirectory defaultFileBasedCertificateDirectory(
            KeyMaterialReaderBackend keyReader,
            SubkeyLookup subkeyLookup)
            throws NotAStoreException {
        return fileBasedCertificateDirectory(keyReader, BaseDirectoryProvider.getDefaultBaseDir(), subkeyLookup);
    }

    public static PGPCertificateDirectory fileBasedCertificateDirectory(
            KeyMaterialReaderBackend keyReader,
            File baseDirectory,
            SubkeyLookup subkeyLookup)
            throws NotAStoreException {
        return new PGPCertificateDirectory(
                new FileBasedCertificateDirectoryBackend(baseDirectory, keyReader), subkeyLookup);
    }
}
