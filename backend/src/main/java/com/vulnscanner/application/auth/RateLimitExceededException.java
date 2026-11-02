package com.vulnscanner.application.auth;

public class RateLimitExceededException extends RuntimeException {
    public static final String MESSAGE = "Too many requests. Please try again later.";

    public RateLimitExceededException() {
        super(MESSAGE);
    }
}
