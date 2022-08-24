// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;

public class TestKeys {
    @SuppressWarnings("CharsetObjectCanBeUsed")
    private static final Charset UTF8 = Charset.forName("UTF8");

    public static final String HARRY_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: 2357 8FD1 7F20 7FDF 62F7  976C 4E9D 9891 7AD8 4522\n" +
            "Comment: Harry Potter <harry@potter.more>\n" +
            "\n" +
            "xVgEYwTP0hYJKwYBBAHaRw8BAQdAPVcWeaMiUVG+vECWpoytSoF3wNJQG/JsnCbj\n" +
            "uQtv0REAAP0cS3GCmrIMO/FqNm1FG1mKw4P+mvZ1JBFILN7Laooq7A/QwsARBB8W\n" +
            "CgCDBYJjBM/SBYkFn6YAAwsJBwkQTp2YkXrYRSJHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
            "dGlvbnMuc2VxdW9pYS1wZ3Aub3JnRSvJhQu9P/3bpFqFdB2c5Mfg9JIdyic1tsAt\n" +
            "lZ7o4k4DFQoIApsBAh4BFiEEI1eP0X8gf99i95dsTp2YkXrYRSIAAK2cAP9juDnY\n" +
            "qB6XuXVx76MzDlFemqJ/r2TIlN22O33ITp23cQEAiMk/rULVdfmlFi3QBvXgtPI2\n" +
            "QQYFI0UnyGLmJSa1cwzNIEhhcnJ5IFBvdHRlciA8aGFycnlAcG90dGVyLm1vcmU+\n" +
            "wsAUBBMWCgCGBYJjBM/SBYkFn6YAAwsJBwkQTp2YkXrYRSJHFAAAAAAAHgAgc2Fs\n" +
            "dEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn0o9na1p+a9kY3y3+xUSFFnxbuxNM\n" +
            "5zvth0SAfJIH2C8DFQoIApkBApsBAh4BFiEEI1eP0X8gf99i95dsTp2YkXrYRSIA\n" +
            "AC1zAP0e2qRXH4zCnjvdYwGP0tIY3dwBsm1bvk+wVFHm8h68iwEAh2uyyQ+O5iQH\n" +
            "7NN/lV5dUKKsKaimj/vVGpSW3NtFZQDHWARjBM/SFgkrBgEEAdpHDwEBB0BUqcZu\n" +
            "VsEO6fmW8q3S5ll9WohcTOWRX7Spg5wS3DIqPgABALzJ9ZImb4U94WqRtftSSaeF\n" +
            "0w6rHCn2DiTT8pxjefGQEW7CwMUEGBYKATcFgmMEz9IFiQWfpgAJEE6dmJF62EUi\n" +
            "RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ+HPX0u5kyKR\n" +
            "5IwErbomgGKVCGuvR6oSKc7CDQYMJS9eApsCvqAEGRYKAG8FgmMEz9IJEKk0hrvR\n" +
            "6Jc7RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ8Chba26\n" +
            "1nQ6ZEZ/rVH8wMhYznGNa/Ux28sodM04wU6dFiEEli7ijJ6quX9gSoSbqTSGu9Ho\n" +
            "lzsAAG1wAQDVvKVWaMOBELROkF72oBH58X6lrOmr08W5FJQxehywhQEAwetpgL1V\n" +
            "DNj4qcvuCJJ2agAM1tA22WMPpQQeA5CCgwcWIQQjV4/RfyB/32L3l2xOnZiRethF\n" +
            "IgAAsWEA/RfOKexMYEtzlpM71MB9SL+emHXf+w1TNAvBxrifU8bMAPoDmWHkWjZQ\n" +
            "N6upbHKssRywPLKCMPLnFYtBNxDrMYr0BMddBGMEz9ISCisGAQQBl1UBBQEBB0CR\n" +
            "p5dCIlSpV/EvXX2+YZnZSRtc8eTFXkph8RArNi0QPAMBCAcAAP9seqRo6mbmvS4h\n" +
            "fkxmV5zap3wIemzW4iabNU2VbWJbEBALwsAGBBgWCgB4BYJjBM/SBYkFn6YACRBO\n" +
            "nZiRethFIkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdx\n" +
            "uRLJ/h81azzvGn5zgJ+jdfkdM6iO+f1CLgfnHUH9ugKbDBYhBCNXj9F/IH/fYveX\n" +
            "bE6dmJF62EUiAACObgEAk4whKEo2nzpWht65tpFjrEXdakj00mA/P612P2CUdPQB\n" +
            "ANNn+VUiu9rtnLcP4NlaUVOwsgN7yyed0orbmG1VvSMF\n" +
            "=cBAn\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    public static final String HARRY_FP = "23578fd17f207fdf62f7976c4e9d98917ad84522";

    public static final String RON_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: B798 AF18 6BFE 4C19 902D  4950 5647 F001 37EF 4C41\n" +
            "Comment: Ron Weasley <ron@weasley.burrow>\n" +
            "\n" +
            "xjMEYwTRXBYJKwYBBAHaRw8BAQdAPHyiu4nwvo3OY3wLG1tUmS6qeTeT1zd3BrL+\n" +
            "6/5Ys3jCwBEEHxYKAIMFgmME0VwFiQWfpgADCwkHCRBWR/ABN+9MQUcUAAAAAAAe\n" +
            "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfEPNi/1ObPMwDwS094Lcyq\n" +
            "dRNRk2FRzvhoXKrqF/GHfQMVCggCmwECHgEWIQS3mK8Ya/5MGZAtSVBWR/ABN+9M\n" +
            "QQAAR/oBAJWxxUJqOAzYG4uAd6SSF55LZVl00t3bGhgEyGmrB/ppAQCZTpWu0rwU\n" +
            "GVv/MoeqRwX+P8sHS4FSu/hSYJpbNwysCM0gUm9uIFdlYXNsZXkgPHJvbkB3ZWFz\n" +
            "bGV5LmJ1cnJvdz7CwBQEExYKAIYFgmME0VwFiQWfpgADCwkHCRBWR/ABN+9MQUcU\n" +
            "AAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmf43PjsP9w1eGYP\n" +
            "CLm6O+K27EQPiCf2cW71QnQ0RunupgMVCggCmQECmwECHgEWIQS3mK8Ya/5MGZAt\n" +
            "SVBWR/ABN+9MQQAA7rYA/3U2aaw5PFa9L90PbxygOwFrgIVWLiOpnKfjqDJqEgva\n" +
            "AQDxTIbpUYEAYmTpmAm1tiQSlpp9P96vqCMIj2OqtYCNAs4zBGME0VwWCSsGAQQB\n" +
            "2kcPAQEHQGzhRPzKRkkce0v1NjuTV2stn8CEMVgnUxsMPtd0h2M9wsDFBBgWCgE3\n" +
            "BYJjBNFcBYkFn6YACRBWR/ABN+9MQUcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5z\n" +
            "ZXF1b2lhLXBncC5vcmd6UNkzsh0jKRPQAKX2PoUhMN4QfhTK9IC6L+QbyL1rFgKb\n" +
            "Ar6gBBkWCgBvBYJjBNFcCRCuGMJD3GUsUUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmcUTns9+sw7XKKO5ZOYQninRAchypKHbqV2LinV46Hi\n" +
            "bxYhBI+SjTgn0fulukOYj64YwkPcZSxRAADZtAEApse3UJi1iuSFvnyXxuYIOm4d\n" +
            "0sOaOtd18venqfWGyX4BALf7T7LknMY688vaW6/xkw2fonG6Y5VxreIHlMZAcX0H\n" +
            "FiEEt5ivGGv+TBmQLUlQVkfwATfvTEEAAFQ3AQCGSLEt8wgJZXlljPdk1eQ3uvW3\n" +
            "VHryNAc3/vbSOvByFAD/WKXY8Pqki2r9XVUW33Q88firoiKVuGmBxklEG3ACjALO\n" +
            "OARjBNFcEgorBgEEAZdVAQUBAQdARnMlx3ST0EHPiErN7lOF+lhtJ8FmW9arc46u\n" +
            "sHFMgUMDAQgHwsAGBBgWCgB4BYJjBNFcBYkFn6YACRBWR/ABN+9MQUcUAAAAAAAe\n" +
            "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfv1PKQX1GMihAdj3ftW/yS\n" +
            "bnPYdE+0h5rGCuhYl7sjaQKbDBYhBLeYrxhr/kwZkC1JUFZH8AE370xBAABWugEA\n" +
            "rWOEHQjzoQkxxsErVEVZjqr05SLMmo6+HMJ/4Sgur10A/0+4FSbaKKNGiCnCMRsZ\n" +
            "BEswoD99mUaBXl1nPH+Hg38O\n" +
            "=+pb5\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    public static final String RON_FP = "b798af186bfe4c19902d49505647f00137ef4c41";

    public static final String CEDRIC_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: 5E75 BF20 646B C1A9 8D3B  1BC2 FE9C D472 987C 4021\n" +
            "Comment: Cedric Diggory <cedric@diggo.ry>\n" +
            "\n" +
            "xjMEYwTIyhYJKwYBBAHaRw8BAQdA80cyaoAEfh/ENuHw8XtWqrxDoPQ/x44LQzyO\n" +
            "TLhMN+PCwBEEHxYKAIMFgmMEyMoFiQWfpgADCwkHCRD+nNRymHxAIUcUAAAAAAAe\n" +
            "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmf0ckQJQzwOKkXPe8rFP5B+\n" +
            "CbAshRG5OKD3Dp+hScGFXgMVCggCmwECHgEWIQRedb8gZGvBqY07G8L+nNRymHxA\n" +
            "IQAA9WYBAP5rQCq/W3KV90T/wpxf5pcXoCB4tCC9Gi/1AiuGhQdAAP48PIX9fH+T\n" +
            "g7N+tU0xzzCc2nWxG3cIuvGFsg94pKL8As0gQ2VkcmljIERpZ2dvcnkgPGNlZHJp\n" +
            "Y0BkaWdnby5yeT7CwBQEExYKAIYFgmMEyMoFiQWfpgADCwkHCRD+nNRymHxAIUcU\n" +
            "AAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdkUL5mF5SwIXja\n" +
            "bCxhI3lvqiUURSoLY13K6YvHYLz7bwMVCggCmQECmwECHgEWIQRedb8gZGvBqY07\n" +
            "G8L+nNRymHxAIQAA6SwA/jiM8k/Z0ljnHdFxsdoLhdnTZ0yJT/7RxreSZ3aITrDs\n" +
            "AP9V8bAYy4hK0C7i4FmNcos3HQs2Si6ee2/EZjo8LqxeCc4zBGMEyMoWCSsGAQQB\n" +
            "2kcPAQEHQIu0hKMngTnmIPXlZ/p9WOZmLB0s9v9yZJLdZ5ICKn7jwsDFBBgWCgE3\n" +
            "BYJjBMjKBYkFn6YACRD+nNRymHxAIUcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5z\n" +
            "ZXF1b2lhLXBncC5vcmdCT1SyOVJwTPp4OEDWFNEgxKD12H+Dya9EzOMJ3I9frwKb\n" +
            "Ar6gBBkWCgBvBYJjBMjKCRDNPli8d9EIkUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmccLTSNIhZOiNFaTj76iAutuAkUCImFp5ptMICZRo7E\n" +
            "TRYhBESzEAYRbxRfM3ub5c0+WLx30QiRAAAZtwD/WRJrSxzJRsnZs4w+QgZjqOZx\n" +
            "bOGwGObfbEHaExG0cKEA/R+BFODg5oPOvK9W7n0Kt9O171Po+zXB0UDmBiEhh0YL\n" +
            "FiEEXnW/IGRrwamNOxvC/pzUcph8QCEAAEneAQDnOv/cf1/qmjfLnorEi+Z4gRWQ\n" +
            "fp3Rp/gI4SLUQxT0PQD/USZIP0bNMGGC1TRQa+8nK6opSqtIvsatt0tQuu178A7O\n" +
            "OARjBMjKEgorBgEEAZdVAQUBAQdAazcEUsYtY9f9o4A+ePR7ACMIDScVEUWS83+I\n" +
            "SwJQz3QDAQgHwsAGBBgWCgB4BYJjBMjKBYkFn6YACRD+nNRymHxAIUcUAAAAAAAe\n" +
            "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmc/qxMatwD+6zaKDZGlVdn/\n" +
            "TWumSgLtuyYonaOupIfMEAKbDBYhBF51vyBka8GpjTsbwv6c1HKYfEAhAADPiwEA\n" +
            "vQ7fTnAHcdZlMVnNPkc0pZSp1+kO5Z789I5Pp4HloNIBAMoC84ja83PjvcpIyxgR\n" +
            "kspLC9BliezVbFSHIK9NQ/wC\n" +
            "=VemI\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    public static final String CEDRIC_FP = "5e75bf20646bc1a98d3b1bc2fe9cd472987c4021";

    public static InputStream getHarryKey() {
        return new ByteArrayInputStream(HARRY_KEY.getBytes(UTF8));
    }

    public static InputStream getRonCert() {
        return new ByteArrayInputStream(RON_CERT.getBytes(UTF8));
    }

    public static InputStream getCedricCert() {
        return new ByteArrayInputStream(CEDRIC_CERT.getBytes(UTF8));
    }
}
