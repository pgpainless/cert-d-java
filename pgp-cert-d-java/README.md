<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Shared PGP Certificate Directory for Java

[![javadoc](https://javadoc.io/badge2/org.pgpainless/pgp-cert-d-java/javadoc.svg)](https://javadoc.io/doc/org.pgpainless/pgp-cert-d-java)
[![Maven Central](https://badgen.net/maven/v/maven-central/org.pgpainless/pgp-cert-d-java)](https://search.maven.org/artifact/org.pgpainless/pgp-cert-d-java)

Backend-agnostic implementation of the [Shared PGP Certificate Directory Specification](https://sequoia-pgp.gitlab.io/pgp-cert-d/).
This module implements the non-OpenPGP parts of the spec, e.g. locating the directory, resolving certificate file paths,
locking the directory for writes etc.

This library can be used on Android API level 26 and up.

To get a useful implementation, a backend implementation such as `pgpainless-cert-d` is required, which needs to provide
support for reading and merging certificates.

`pgp-cert-d-java` can be used as an implementation of `pgp-certificate-store` using the `PGPCertificateStoreAdapter` class.

Note: This is a library module. For a command line interface, see [pgpainless-cert-d-cli](https://github.com/pgpainless/cert-d-pgpainless/tree/main/pgpainless-cert-d-cli).
