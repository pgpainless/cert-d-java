// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.File;

/**
 * Provider class that is responsible for resolving the pgp.cert.d base directory of the system.
 * The result can be overwritten by setting the <pre>PGP_CERT_D</pre> environment variable.
 * If this variable is not set, the system-specific default directory will be returned.
 *
 * On Windows systems, this is <pre>%APPDATA%\pgp.cert.d</pre>.
 * On Linux systems it is either <pre>$XDG_DATA_HOME/pgp.cert.d</pre> or, if <pre>$XDG_DATA_HOME</pre> is not set,
 * it is <pre>$HOME/.local/share/pgp.cert.d</pre>
 * On Mac systems it is <pre>$HOME/Library/Application Support/pgp.cert.d</pre>.
 */
public class BaseDirectoryProvider {

    public static File getDefaultBaseDir() {
        // Check for environment variable
        String baseDirFromEnv = System.getenv("PGP_CERT_D");
        if (baseDirFromEnv != null) {
            return new File(baseDirFromEnv);
        }

        // return OS-specific default dir
        String osName = System.getProperty("os.name", "generic")
                .toLowerCase();
        return getDefaultBaseDirForOS(osName);
    }

    public static File getDefaultBaseDirForOS(String osName) {
        String STORE_NAME = "pgp.cert.d";
        if (osName.contains("win")) {
            // %APPDATA%\Roaming\pgp.cert.d
            String app_data = System.getenv("APPDATA");
            if (app_data == null) {
                throw new AssertionError("Cannot determine APPDATA directory.");
            }
            File roaming = new File(app_data, "Roaming");
            return new File(roaming, STORE_NAME);
        }

        if (osName.contains("nux")) {
            // $XDG_DATA_HOME/pgp.cert.d
            String xdg_data_home = System.getenv("XDG_DATA_HOME");
            if (xdg_data_home != null) {
                return new File(xdg_data_home, STORE_NAME);
            }
            String user_home = System.getProperty("user.home");
            if (user_home == null) {
                throw new AssertionError("Cannot determine user.home directory.");
            }
            // $HOME/.local/share/pgp.cert.d
            File local = new File(user_home, ".local");
            File share = new File(local, "share");
            return new File(share, STORE_NAME);
        }

        if (osName.contains("mac")) {
            String home = System.getenv("HOME");
            if (home == null) {
                throw new AssertionError("Cannot determine HOME directory.");
            }
            File library = new File(home, "Library");
            File applicationSupport = new File(library, "Application Support");
            return new File(applicationSupport, STORE_NAME);
        }

        throw new IllegalArgumentException("Unknown OS " + osName);
    }

}
