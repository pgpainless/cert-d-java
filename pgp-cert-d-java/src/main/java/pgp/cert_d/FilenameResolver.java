// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.exception.BadNameException;

import java.io.File;
import java.util.regex.Pattern;

public class FilenameResolver {

    private final File baseDirectory;
    private final Pattern openPgpV4FingerprintPattern = Pattern.compile("^[a-f0-9]{40}$");

    public FilenameResolver(File baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    public File getBaseDirectory() {
        return baseDirectory;
    }

    /**
     * Calculate the file location for the certificate addressed by the given
     * lowercase hexadecimal OpenPGP fingerprint.
     *
     * @param fingerprint fingerprint
     * @return absolute certificate file location
     *
     * @throws BadNameException if the given fingerprint string is not a fingerprint
     */
    public File getCertFileByFingerprint(String fingerprint) throws BadNameException {
        if (!isFingerprint(fingerprint)) {
            throw new BadNameException();
        }

        // is fingerprint
        File subdirectory = new File(getBaseDirectory(), fingerprint.substring(0, 2));
        File file = new File(subdirectory, fingerprint.substring(2));
        return file;
    }

    /**
     * Calculate the file location for the certification addressed using the given special name.
     * For known special names, see {@link SpecialNames}.
     *
     * @param specialName special name (e.g. "trust-root")
     * @return absolute certificate file location
     *
     * @throws BadNameException in case the given special name is not known
     */
    public File getCertFileBySpecialName(String specialName)
            throws BadNameException {
        if (!isSpecialName(specialName)) {
            throw new BadNameException(String.format("%s is not a known special name", specialName));
        }

        return new File(getBaseDirectory(), specialName);
    }

    /**
     * Calculate the file location for the key addressed using the given special name.
     * For known special names, see {@link SpecialNames}.
     *
     * @param specialName special name (e.g. "trust-root")
     * @return absolute key file location
     *
     * @throws BadNameException in case the given special name is not known
     */
    public File getKeyFileBySpecialName(String specialName)
            throws BadNameException {
        if (!isSpecialName(specialName)) {
            throw new BadNameException(String.format("%s is not a known special name", specialName));
        }

        return new File(getBaseDirectory(), specialName + ".key");
    }

    private boolean isFingerprint(String fingerprint) {
        return openPgpV4FingerprintPattern.matcher(fingerprint).matches();
    }

    private boolean isSpecialName(String specialName) {
        return SpecialNames.lookupSpecialName(specialName) != null;
    }

}
