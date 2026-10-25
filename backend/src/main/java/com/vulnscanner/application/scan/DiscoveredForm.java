package com.vulnscanner.application.scan;

import java.util.List;

public record DiscoveredForm(String actionUrl, String method, List<String> parameterNames) {
    public DiscoveredForm {
        parameterNames = parameterNames == null ? List.of() : List.copyOf(parameterNames);
    }
}
