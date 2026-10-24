package com.vulnscanner.application.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class ApiExceptionHandler {

    // Without this handler, @Valid failures on anonymous (permitAll) endpoints such as
    // /api/auth/register fall through to Spring MVC's default handling, which performs an
    // internal forward to /error. That forwarded request re-enters the Spring Security filter
    // chain as a brand-new, unauthenticated request and is rejected with 401 Access Denied
    // instead of the intended 400 response with field errors. Handling the exception here keeps
    // it inside normal controller-advice dispatch, so it never reaches /error or the security
    // filter chain a second time.
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(
            MethodArgumentNotValidException exception, HttpServletRequest request) {
        Map<String, String> fieldErrors = exception.getBindingResult().getFieldErrors().stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        fieldError -> fieldError.getDefaultMessage() != null
                                ? fieldError.getDefaultMessage()
                                : "Invalid value",
                        (existing, replacement) -> existing,
                        LinkedHashMap::new));
        String message = fieldErrors.isEmpty()
                ? "Validation failed"
                : "Validation failed: " + String.join("; ", fieldErrors.values());
        return response(HttpStatus.BAD_REQUEST, message, request);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthentication(
            AuthenticationException exception, HttpServletRequest request) {
        return response(HttpStatus.UNAUTHORIZED, "Unauthorized", request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException exception, HttpServletRequest request) {
        return response(HttpStatus.FORBIDDEN, "Access is denied", request);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRequest(
            IllegalArgumentException exception, HttpServletRequest request) {
        return response(HttpStatus.BAD_REQUEST, exception.getMessage(), request);
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleInvalidState(
            IllegalStateException exception, HttpServletRequest request) {
        return response(HttpStatus.CONFLICT, exception.getMessage(), request);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleConflict(HttpServletRequest request) {
        return response(HttpStatus.CONFLICT, "Registration conflicts with existing data", request);
    }

    private ResponseEntity<ErrorResponse> response(HttpStatus status, String message, HttpServletRequest request) {
        return ResponseEntity.status(status).body(new ErrorResponse(
                status.value(), status.getReasonPhrase(), message, request.getRequestURI(), Instant.now()));
    }
}
