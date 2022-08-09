// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.Certificate;
import pgp.certificate_store.KeyMaterial;
import pgp.certificate_store.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;

public interface WritingPGPCertificateDirectory {

    KeyMaterial getTrustRoot()
            throws IOException, BadDataException;

    KeyMaterial insertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, InterruptedException;

    KeyMaterial tryInsertTrustRoot(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException;

    Certificate insert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, InterruptedException;

    Certificate tryInsert(InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException;

    Certificate insertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException, InterruptedException;

    Certificate tryInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge)
            throws IOException, BadDataException, BadNameException;

}