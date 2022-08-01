<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Shared PGP Certificate Directory for Java
[![status-badge](https://ci.codeberg.org/api/badges/PGPainless/cert-d-java/status.svg?branch=main)](https://ci.codeberg.org/PGPainless/cert-d-java)
[![Coverage Status](https://coveralls.io/repos/github/pgpainless/cert-d-java/badge.svg?branch=main)](https://coveralls.io/github/pgpainless/cert-d-java?branch=main)
[![REUSE status](https://api.reuse.software/badge/github.com/pgpainless/cert-d-java)](https://api.reuse.software/info/github.com/pgpainless/cert-d-java)

This repository contains a number of modules defining OpenPGP certificate storage for Java and Android applications.

The module [pgp-certificate-store](pgp-certificate-store] defines generalized
interfaces for OpenPGP Certificate storage.
It can be used by applications and libraries such as
[PGPainless](https://pgpainless.org/) for certificate management.

The module [pgp-cert-d-java](pgp-cert-d-java) contains an implementation of
the [Shared PGP Certificate Directory](https://sequoia-pgp.gitlab.io/pgp-cert-d/)
which can also be used as a backend for the `pgp-certificate-store` interfaces.

Lastly, the module [pgp-cert-d-java-jdbc-sqlite-lookup](pgp-cert-d-java-jdbc-sqlite-lookup)
contains an implementation of the `SubkeyLookup` interface using an sqlite database.
