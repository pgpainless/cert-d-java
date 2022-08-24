<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <info@pgpainless.org>
SPDX-License-Identifier: CC0-1.0
-->

# Cert-D-Java Changelog

## 0.1.2-SNAPSHOT
- `pgp-certificate-store`:
  - Rework `Certificate`, `Key` to inherit from `KeyMaterial`
  - Rename `CertificateReaderBackend` to `KeyMaterialReaderBackend`
  - Rename `CertificateMerger` to `KeyMaterialMerger`
  - Rework `PGPCertificateStore` class
- `pgp-cert-d-java`:
  - Rework `PGPCertificateDirectory` class by separating out backend logic
  - Split interface into `ReadOnlyPGPCertificateDirectory` and `WritingPGPCertificateDirectory`
- `pgp-cert-d-java-jdbc-sqlite-lookup`:
  - Add `DatabaseSubkeyLookupFactory`

## 0.1.1
- Bump `slf4j` to `1.7.36`
- Bump `logback` to `1.2.11` 

## 0.1.0
- Initial Release
