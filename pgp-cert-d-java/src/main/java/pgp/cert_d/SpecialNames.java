// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.util.HashMap;
import java.util.Map;

public class SpecialNames {

    public static final String TRUST_ROOT = "trust-root";

    // Map to allow for potentially upper- and lowercase variants of the same special name
    private static final Map<String, String> SPECIAL_NAMES = new HashMap<>();

    static {
        SPECIAL_NAMES.put("TRUST-ROOT", TRUST_ROOT); // TODO: Remove
        SPECIAL_NAMES.put(TRUST_ROOT, TRUST_ROOT);
    }

    public static String lookupSpecialName(String specialName) {
        return SPECIAL_NAMES.get(specialName);
    }
}
