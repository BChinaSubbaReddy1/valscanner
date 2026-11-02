package com.vulnscanner.application.common;

import java.net.URI;
import java.util.Arrays;
import java.util.stream.Collectors;

public final class UrlSanitizer {
    private UrlSanitizer() {
    }

    public static String safeEndpoint(String value) {
        return safeUrl(value, true);
    }

    public static String safeTargetUrl(String value) {
        return safeUrl(value, false);
    }

    private static String safeUrl(String value, boolean includeRootPath) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(value);
            if (!uri.isAbsolute() || uri.isOpaque() || uri.getRawUserInfo() != null
                    || uri.getHost() == null
                    || (!"http".equalsIgnoreCase(uri.getScheme())
                    && !"https".equalsIgnoreCase(uri.getScheme()))) {
                return null;
            }
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty()
                    ? (includeRootPath ? "/" : "")
                    : uri.getRawPath();
            String queryNames = uri.getRawQuery() == null ? "" : Arrays.stream(uri.getRawQuery().split("&"))
                    .map(part -> part.split("=", 2)[0])
                    .filter(name -> !name.isBlank())
                    .distinct()
                    .collect(Collectors.joining("&", "?", ""));
            return uri.getScheme() + "://" + uri.getRawAuthority() + path + queryNames;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
