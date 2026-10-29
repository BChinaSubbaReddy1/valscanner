package com.vulnscanner.application.scan;

public record ZapAlert(
        String pluginId,
        String alert,
        String risk,
        String confidence,
        String url,
        String param,
        String attack,
        String evidence,
        String description,
        String solution,
        String reference,
        String cweid,
        String wascid,
        String id
) {
    public ZapAlert(
            String pluginId,
            String alert,
            String risk,
            String confidence,
            String url,
            String param,
            String attack,
            String evidence,
            String description,
            String solution,
            String reference,
            String cweid,
            String wascid
    ) {
        this(pluginId, alert, risk, confidence, url, param, attack, evidence,
                description, solution, reference, cweid, wascid, null);
    }
}
