// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.certificate.Certificate;
import pgp.certificate.KeyMaterial;
import pgp.certificate.KeyMaterialMerger;

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
