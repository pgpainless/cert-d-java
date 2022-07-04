// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

/**
 * Secret key store definition for trust-root keys.
 */
public interface TrustRootStore {

    /**
     * Return the current trust-root key.
     * If no trust-root key is present, return null.
     *
     * @return trust-root key
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the key datum contains invalid data
     */
    Key getTrustRoot()
            throws IOException, BadDataException;

    /**
     * Return the current trust-root key, but only iff it changed since the last invocation of this method.
     * To compare the key against its last returned result, the given tag is used.
     * If the tag of the currently found key matches the given argument, return null.
     *
     * @param tag tag to compare freshness
     * @return changed key or null
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the key datum contains invalid data
     */
    Key getTrustRootIfChanged(String tag)
            throws IOException, BadDataException;

    /**
     * Insert the given trust-root key into the store.
     * If the key store already holds a trust-root key, the given {@link KeyMerger} callback will be used to merge
     * the two instances into one {@link Key}. The result will be stored in the store and returned.
     *
     * This method will not block. Instead, if the store is already write-locked, this method will simply return null
     * without writing anything.
     * However, if the write-lock is available, this method will acquire the lock, write to the store, release the lock
     * and return the written key.
     *
     * @param data input stream containing the new trust-root key
     * @param keyMerger callback for merging with an existing key instance
     * @return merged key
     *
     * @throws IOException in case of an IO error
     * @throws InterruptedException in case the inserting thread gets interrupted
     * @throws BadDataException if the data stream does not contain a valid OpenPGP key
     */
    Key insertTrustRoot(InputStream data, KeyMerger keyMerger)
            throws IOException, InterruptedException, BadDataException;

    /**
     * Insert the given trust-root key into the store.
     * If the key store already holds a trust-root key, the given {@link KeyMerger} callback will be used to merge
     * the two instances into one {@link Key}. The result will be stored in the store and returned.
     *
     * This method will block until a write-lock on the store can be acquired. If you cannot afford blocking,
     * consider using {@link #tryInsertTrustRoot(InputStream, KeyMerger)} instead.
     *
     * @param data input stream containing the new trust-root key
     * @param keyMerger callback for merging with an existing key instance
     * @return merged key
     *
     * @throws IOException in case of an IO error
     * @throws BadDataException if the data stream does not contain a valid OpenPGP key
     */
    Key tryInsertTrustRoot(InputStream data, KeyMerger keyMerger)
        throws IOException, BadDataException;
}
