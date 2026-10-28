package com.vulnscanner.application.scan;

public enum NvdLookupStatus {
    NOT_REQUESTED,
    DISABLED,
    CANDIDATES_FOUND,
    NO_CANDIDATES,
    UNAVAILABLE,
    TIMEOUT,
    RATE_LIMITED,
    INVALID_RESPONSE,
    PARTIAL_RESULTS;

    public NvdLookupStatus merge(NvdLookupStatus next) {
        if (next == null || next == NOT_REQUESTED) {
            return this;
        }
        if (this == NOT_REQUESTED) {
            return next;
        }
        if (this == next) {
            return this;
        }
        if (this == PARTIAL_RESULTS || next == PARTIAL_RESULTS) {
            return PARTIAL_RESULTS;
        }
        boolean thisSuccessful = this == CANDIDATES_FOUND || this == NO_CANDIDATES;
        boolean nextSuccessful = next == CANDIDATES_FOUND || next == NO_CANDIDATES;
        if (thisSuccessful && nextSuccessful) {
            return this == CANDIDATES_FOUND || next == CANDIDATES_FOUND
                    ? CANDIDATES_FOUND : NO_CANDIDATES;
        }
        return PARTIAL_RESULTS;
    }
}
