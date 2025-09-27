<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <info@pgpainless.org>
SPDX-License-Identifier: CC0-1.0
-->

# Cert-D-Java Changelog

## 0.2.3
- Bump Bouncy Castle to `1.82` and switch to `jdk18on`-variants
- Upgrade build system
  - Bump gradle to `8.8`
  - Bump logback to `1.5.13`
  - Raise minimal JVM level to 11

## 0.2.2
- Bump Bouncy Castle to `1.75`
- Bump `sqlite-jdbc` to `3.42.0.0`

## 0.2.1
- Throw `NoSuchElementException` when querying non-existent certificates

## 0.2.0
- `pgp-certificate-store`:
  - Rework `Certificate`, `Key` to inherit from `KeyMaterial`
  - Rename `CertificateReaderBackend` to `KeyMaterialReaderBackend`
  - Rename `CertificateMerger` to `KeyMaterialMerger`
  - Rework `PGPCertificateStore` class
- `pgp-cert-d-java`:
  - Increase minimum Android API level to 26
  - Add `PGPCertificateDirectories` factory class
  - Rework `PGPCertificateDirectory` class by separating out backend logic
  - Split interface into `ReadOnlyPGPCertificateDirectory` and `WritingPGPCertificateDirectory`
  - `FileBasedCertificateDirectoryBackend`: Calculate tag based on file attributes (inode)
- `pgp-cert-d-java-jdbc-sqlite-lookup`:
  - Add `DatabaseSubkeyLookupFactory`

## 0.1.1
- Bump `slf4j` to `1.7.36`
- Bump `logback` to `1.2.11` 

## 0.1.0
- Initial Release
