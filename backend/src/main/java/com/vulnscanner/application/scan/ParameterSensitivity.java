package com.vulnscanner.application.scan;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;

final class ParameterSensitivity {
    private static final Set<String> SENSITIVE_PREFIXES = Set.of(
            "password", "passwd", "secret", "token", "session", "cookie", "csrf", "passcode", "otp");
    private static final Set<String> SENSITIVE_NAMES = Set.of(
            "password", "passwd", "secret", "token", "session", "cookie", "csrf", "pin", "passcode",
            "otp", "auth", "authorization", "authentication", "oauth", "api_key", "apikey", "access_key",
            "accesskey", "client_key", "clientkey", "private_key", "privatekey", "public_key", "publickey",
            "secret_key", "secretkey", "encryption_key", "encryptionkey", "signing_key", "signingkey",
            "ssh_key", "sshkey", "sessionid", "sessiontoken", "csrftoken");

    private ParameterSensitivity() {
    }

    static boolean isSensitive(String name) {
        if (name == null || name.isBlank()) {
            return false;
        }
        String segmented = name.replaceAll("([a-z0-9])([A-Z])", "$1_$2")
                .toLowerCase(Locale.ROOT);
        return Arrays.stream(segmented.split("[^a-z0-9]+"))
                .anyMatch(ParameterSensitivity::isSensitiveToken);
    }

    private static boolean isSensitiveToken(String token) {
        return SENSITIVE_NAMES.contains(token)
                || SENSITIVE_PREFIXES.stream().anyMatch(token::startsWith);
    }
}
