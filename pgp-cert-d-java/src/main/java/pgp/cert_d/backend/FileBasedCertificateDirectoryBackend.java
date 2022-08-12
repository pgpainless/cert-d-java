// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.backend;

import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.SpecialNames;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;
import pgp.certificate_store.exception.NotAStoreException;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

public class FileBasedCertificateDirectoryBackend implements PGPCertificateDirectory.Backend {

    private abstract static class Lazy<E> {
        abstract E get() throws BadDataException;
    }

    private static class FileLockingMechanism implements PGPCertificateDirectory.LockingMechanism {

        private final File lockFile;
        private RandomAccessFile randomAccessFile;
        private FileLock fileLock;

        FileLockingMechanism(File lockFile) {
            this.lockFile = lockFile;
        }

        public static FileLockingMechanism defaultDirectoryFileLock(File baseDirectory) {
            return new FileLockingMechanism(new File(baseDirectory, "writelock"));
        }

        @Override
        public synchronized void lockDirectory() throws IOException, InterruptedException {
            if (randomAccessFile != null) {
                // we own the lock already. Let's wait...
                this.wait();
            }

            try {
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            } catch (FileNotFoundException e) {
                lockFile.createNewFile();
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            }

            fileLock = randomAccessFile.getChannel().lock();
        }

        @Override
        public synchronized boolean tryLockDirectory() throws IOException {
            if (randomAccessFile != null) {
                // We already locked the directory for another write operation.
                // We fail, since we have not yet released the lock from the other operation.
                return false;
            }

            try {
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            } catch (FileNotFoundException e) {
                lockFile.createNewFile();
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            }

            try {
                fileLock = randomAccessFile.getChannel().tryLock();
                if (fileLock == null) {
                    // try-lock failed, file is locked by another process.
                    randomAccessFile.close();
                    randomAccessFile = null;
                    return false;
                }
            } catch (OverlappingFileLockException e) {
                // Some other object is holding the lock.
                randomAccessFile.close();
                randomAccessFile = null;
                return false;
            }
            return true;
        }

        @Override
        public boolean isLocked() {
            return randomAccessFile != null;
        }

        @Override
        public synchronized void releaseDirectory() throws IOException {
            // unlock file
            if (fileLock != null) {
                fileLock.release();
                fileLock = null;
            }
            // close file
            if (randomAccessFile != null) {
                randomAccessFile.close();
                randomAccessFile = null;
            }
            // delete file
            if (lockFile.exists()) {
                lockFile.delete();
            }
            // notify waiters
            this.notify();
        }
    }

    private final File baseDirectory;
    private final PGPCertificateDirectory.LockingMechanism lock;
    private final FilenameResolver resolver;
    private final KeyMaterialReaderBackend reader;

    public FileBasedCertificateDirectoryBackend(File baseDirectory, KeyMaterialReaderBackend reader) throws NotAStoreException {
        this.baseDirectory = baseDirectory;
        this.resolver = new FilenameResolver(baseDirectory);

        if (!baseDirectory.exists()) {
            if (!baseDirectory.mkdirs()) {
                throw new NotAStoreException("Cannot create base directory '" + resolver.getBaseDirectory().getAbsolutePath() + "'");
            }
        } else {
            if (baseDirectory.isFile()) {
                throw new NotAStoreException("Base directory '" + resolver.getBaseDirectory().getAbsolutePath() + "' appears to be a file.");
            }
        }
        this.lock = FileLockingMechanism.defaultDirectoryFileLock(baseDirectory);
        this.reader = reader;
    }

    @Override
    public PGPCertificateDirectory.LockingMechanism getLock() {
        return lock;
    }

    @Override
    public Certificate readByFingerprint(String fingerprint) throws BadNameException, IOException, BadDataException {
        File certFile = resolver.getCertFileByFingerprint(fingerprint);
        if (!certFile.exists()) {
            return null;
        }

        FileInputStream fileIn = new FileInputStream(certFile);
        BufferedInputStream bufferedIn = new BufferedInputStream(fileIn);

        Certificate certificate = reader.read(bufferedIn).asCertificate();
        if (!certificate.getFingerprint().equals(fingerprint)) {
            // TODO: Figure out more suitable exception
            throw new BadDataException();
        }

        return certificate;
    }

    @Override
    public KeyMaterial readBySpecialName(String specialName) throws BadNameException, IOException, BadDataException {
        File certFile = resolver.getCertFileBySpecialName(specialName);
        if (!certFile.exists()) {
            return null;
        }

        FileInputStream fileIn = new FileInputStream(certFile);
        BufferedInputStream bufferedIn = new BufferedInputStream(fileIn);
        KeyMaterial keyMaterial = reader.read(bufferedIn);

        return keyMaterial;
    }

    @Override
    public Iterator<Certificate> readItems() {
        return new Iterator<Certificate>() {

            private final List<Lazy<Certificate>> certificateQueue = Collections.synchronizedList(new ArrayList<>());

            // Constructor... wtf.
            {
                File[] subdirectories = baseDirectory.listFiles(new FileFilter() {
                    @Override
                    public boolean accept(File file) {
                        return file.isDirectory() && file.getName().matches("^[a-f0-9]{2}$");
                    }
                });

                for (File subdirectory : subdirectories) {
                    File[] files = subdirectory.listFiles(new FileFilter() {
                        @Override
                        public boolean accept(File file) {
                            return file.isFile() && file.getName().matches("^[a-f0-9]{38}$");
                        }
                    });

                    for (File certFile : files) {
                        certificateQueue.add(new Lazy<Certificate>() {
                            @Override
                            Certificate get() throws BadDataException {
                                try {
                                    Certificate certificate = reader.read(new FileInputStream(certFile)).asCertificate();
                                    if (!(subdirectory.getName() + certFile.getName()).equals(certificate.getFingerprint())) {
                                        throw new BadDataException();
                                    }
                                    return certificate;
                                } catch (IOException e) {
                                    throw new AssertionError("File got deleted.");
                                }
                            }
                        });
                    }
                }
            }

            @Override
            public boolean hasNext() {
                return !certificateQueue.isEmpty();
            }

            @Override
            public Certificate next() {
                try {
                    return certificateQueue.remove(0).get();
                } catch (BadDataException e) {
                    throw new AssertionError("Could not retrieve item: " + e.getMessage());
                }
            }
        };
    }

    @Override
    public KeyMaterial doInsertTrustRoot(InputStream data, KeyMaterialMerger merge) throws BadDataException, IOException {
        KeyMaterial newCertificate = reader.read(data);
        KeyMaterial existingCertificate;
        File certFile;
        try {
            existingCertificate = readBySpecialName(SpecialNames.TRUST_ROOT);
            certFile = resolver.getCertFileBySpecialName(SpecialNames.TRUST_ROOT);
        } catch (BadNameException e) {
            throw new BadDataException();
        }

        if (existingCertificate != null && !newCertificate.getTag().equals(existingCertificate.getTag())) {
            newCertificate = merge.merge(newCertificate, existingCertificate);
        }

        writeToFile(newCertificate.getInputStream(), certFile);

        return newCertificate;
    }

    @Override
    public Certificate doInsert(InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException {
        KeyMaterial newCertificate = reader.read(data);
        Certificate existingCertificate;
        File certFile;
        try {
            existingCertificate = readByFingerprint(newCertificate.getFingerprint());
            certFile = resolver.getCertFileByFingerprint(newCertificate.getFingerprint());
        } catch (BadNameException e) {
            throw new BadDataException();
        }

        if (existingCertificate != null && !newCertificate.getTag().equals(existingCertificate.getTag())) {
            newCertificate = merge.merge(newCertificate, existingCertificate);
        }

        writeToFile(newCertificate.getInputStream(), certFile);

        return newCertificate.asCertificate();
    }

    @Override
    public Certificate doInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException, BadNameException {
        KeyMaterial newCertificate = reader.read(data);
        KeyMaterial existingCertificate;
        File certFile;
        try {
            existingCertificate = readBySpecialName(specialName);
            certFile = resolver.getCertFileBySpecialName(specialName);
        } catch (BadNameException e) {
            throw new BadDataException();
        }

        if (existingCertificate != null && !newCertificate.getTag().equals(existingCertificate.getTag())) {
            newCertificate = merge.merge(newCertificate, existingCertificate);
        }

        writeToFile(newCertificate.getInputStream(), certFile);

        return newCertificate.asCertificate();
    }

    private void writeToFile(InputStream inputStream, File certFile)
            throws IOException {
        certFile.getParentFile().mkdirs();
        if (!certFile.exists() && !certFile.createNewFile()) {
            throw new IOException("Could not create cert file " + certFile.getAbsolutePath());
        }

        FileOutputStream fileOut = new FileOutputStream(certFile);

        byte[] buffer = new byte[4096];
        int read;
        while ((read = inputStream.read(buffer)) != -1) {
            fileOut.write(buffer, 0, read);
        }

        inputStream.close();
        fileOut.close();
    }

    public static class FilenameResolver {

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
}
