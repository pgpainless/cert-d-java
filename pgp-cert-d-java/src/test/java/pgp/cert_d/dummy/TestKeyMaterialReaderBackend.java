// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.dummy;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.Key;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class TestKeyMaterialReaderBackend implements KeyMaterialReaderBackend {

    KeyFingerPrintCalculator fpCalc = new BcKeyFingerprintCalculator();

    @Override
    public KeyMaterial read(InputStream data, Long tag) throws IOException, BadDataException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(data, out);

        try {
            return readKey(new ByteArrayInputStream(out.toByteArray()), tag);
        } catch (IOException | PGPException e) {
            try {
                return readCertificate(new ByteArrayInputStream(out.toByteArray()), tag);
            } catch (IOException e1) {
                throw new BadDataException("Cannot read certificate", e1);
            }
        }
    }

    private Key readKey(InputStream inputStream, Long tag) throws IOException, PGPException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(inputStream, buffer);
        inputStream.close();

        InputStream decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(buffer.toByteArray()));

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(decoderStream, fpCalc);
        PGPPublicKeyRing cert = extractCert(secretKeys);
        ByteArrayInputStream encoded = new ByteArrayInputStream(cert.getEncoded());
        Certificate certificate = readCertificate(encoded, tag);

        return new Key(buffer.toByteArray(), certificate, tag);
    }

    private Certificate readCertificate(InputStream inputStream, Long tag) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(inputStream, buffer);
        ByteArrayInputStream in = new ByteArrayInputStream(buffer.toByteArray());
        InputStream decoderStream = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRing cert = new PGPPublicKeyRing(decoderStream, fpCalc);
        String fingerprint = Hex.toHexString(cert.getPublicKey().getFingerprint()).toLowerCase();
        List<Long> subKeyIds = getSubkeyIds(cert);
        return new Certificate(buffer.toByteArray(), fingerprint, subKeyIds, tag);
    }

    private PGPPublicKeyRing extractCert(PGPSecretKeyRing secretKeys) {
        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = secretKeys.getPublicKeys();
        while (publicKeyIterator.hasNext()) {
            publicKeyList.add(publicKeyIterator.next());
        }
        return new PGPPublicKeyRing(publicKeyList);
    }

    private static List<Long> getSubkeyIds(PGPKeyRing keyRing) {
        List<Long> keyIds = new ArrayList<>();
        Iterator<PGPPublicKey> keys = keyRing.getPublicKeys();
        while (keys.hasNext()) {
            keyIds.add(keys.next().getKeyID());
        }
        return keyIds;
    }
}
