// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.cert_d.subkey_lookup.SubkeyLookupFactory;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;

/**
 * Implementation of {@link SubkeyLookupFactory} which creates a SQLite-based {@link DatabaseSubkeyLookup}.
 */
public class DatabaseSubkeyLookupFactory implements SubkeyLookupFactory {

    private String databaseName;

    public DatabaseSubkeyLookupFactory() {
        this("_pgpainless_subkey_map.db");
    }

    public DatabaseSubkeyLookupFactory(String databaseName) {
        this.databaseName = databaseName;
    }

    @Override
    public SubkeyLookup createFileBasedInstance(File baseDirectory) {
        File databaseFile = new File(baseDirectory, databaseName);
        SubkeyLookupDao dao;
        try {
            if (!databaseFile.exists()) {
                databaseFile.createNewFile();
            }
            dao = SqliteSubkeyLookupDaoImpl.forDatabaseFile(databaseFile);
        } catch (SQLException | IOException e) {
            throw new RuntimeException(e);
        }
        return new DatabaseSubkeyLookup(dao);
    }
}
