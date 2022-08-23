// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

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
    public KeyMaterial read(InputStream data) throws IOException, BadDataException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(data, out);

        try {
            Key key = readKey(new ByteArrayInputStream(out.toByteArray()));
            return key;
        } catch (IOException | PGPException e) {
            try {
                Certificate certificate = readCertificate(new ByteArrayInputStream(out.toByteArray()));
                return certificate;
            } catch (IOException e1) {
                throw new BadDataException();
            }
        }
    }

    private Key readKey(InputStream inputStream) throws IOException, PGPException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(inputStream, buffer);
        inputStream.close();

        InputStream decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(buffer.toByteArray()));

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(decoderStream, fpCalc);
        PGPPublicKeyRing cert = extractCert(secretKeys);
        ByteArrayInputStream encoded = new ByteArrayInputStream(cert.getEncoded());
        Certificate certificate = readCertificate(encoded);

        return new Key() {
            @Override
            public Certificate getCertificate() {
                return certificate;
            }

            @Override
            public String getFingerprint() {
                return certificate.getFingerprint();
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return new ByteArrayInputStream(buffer.toByteArray());
            }

            @Override
            public String getTag() throws IOException {
                return null;
            }

            @Override
            public List<Long> getSubkeyIds() throws IOException {
                return certificate.getSubkeyIds();
            }
        };
    }

    private Certificate readCertificate(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Streams.pipeAll(inputStream, buffer);
        ByteArrayInputStream in = new ByteArrayInputStream(buffer.toByteArray());
        InputStream decoderStream = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRing cert = new PGPPublicKeyRing(decoderStream, fpCalc);
        return new Certificate() {
            @Override
            public String getFingerprint() {
                return Hex.toHexString(cert.getPublicKey().getFingerprint()).toLowerCase();
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return new ByteArrayInputStream(buffer.toByteArray());
            }

            @Override
            public String getTag() throws IOException {
                return null;
            }

            @Override
            public List<Long> getSubkeyIds() throws IOException {
                return TestKeyMaterialReaderBackend.getSubkeyIds(cert);
            }
        };
    }

    private PGPPublicKeyRing extractCert(PGPSecretKeyRing secretKeys) {
        List<PGPPublicKey> publicKeyList = new ArrayList<>();
        Iterator<PGPPublicKey> publicKeyIterator = secretKeys.getPublicKeys();
        while (publicKeyIterator.hasNext()) {
            publicKeyList.add(publicKeyIterator.next());
        }
        PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicKeyList);
        return publicKeyRing;
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
