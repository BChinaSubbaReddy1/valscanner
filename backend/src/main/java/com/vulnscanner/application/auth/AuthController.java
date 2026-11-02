package com.vulnscanner.application.auth;

import com.vulnscanner.application.common.ApiResponse;
import com.vulnscanner.application.user.User;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;
    private final LoginOtpService loginOtpService;

    public AuthController(AuthService authService, LoginOtpService loginOtpService) {
        this.authService = authService;
        this.loginOtpService = loginOtpService;
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginOtpChallengeResponse>> login(
            @Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        LoginOtpChallengeResponse challenge =
                loginOtpService.startLogin(request, servletRequest.getRemoteAddr());
        return ResponseEntity.accepted().body(ApiResponse.success(
                "A login verification code has been sent.", challenge));
    }

    @PostMapping("/verify-login-otp")
    public ResponseEntity<ApiResponse<Map<String, Object>>> verifyLoginOtp(
            @Valid @RequestBody LoginOtpVerificationRequest request,
            HttpServletRequest servletRequest) {
        LoginResponse loginResponse = loginOtpService.verify(request, servletRequest.getRemoteAddr())
                .orElseThrow(() -> new IllegalArgumentException("Login verification is invalid or expired"));
        return ResponseEntity.ok(ApiResponse.success("Login successful", Map.of(
                "token", loginResponse.token(),
                "tokenType", loginResponse.tokenType(),
                "userId", loginResponse.userId(),
                "email", loginResponse.email(),
                "roles", loginResponse.roles()
        )));
    }

    @PostMapping("/resend-login-otp")
    public ResponseEntity<ApiResponse<LoginOtpChallengeResponse>> resendLoginOtp(
            @Valid @RequestBody LoginOtpResendRequest request,
            HttpServletRequest servletRequest) {
        LoginOtpChallengeResponse challenge = loginOtpService.resend(request, servletRequest.getRemoteAddr())
                .orElseThrow(() -> new IllegalArgumentException("Login verification is invalid or expired"));
        return ResponseEntity.accepted().body(ApiResponse.success(
                "A login verification code has been sent.", challenge));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        authService.logout(authHeader);
        return ResponseEntity.ok(ApiResponse.success("Logged out successfully", null));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
                                                               HttpServletRequest servletRequest) {
        authService.requestPasswordReset(request, servletRequest.getRemoteAddr());
        return ResponseEntity.ok(ApiResponse.success(
                "If an account matches that email, a verification code will be sent.", null));
    }

    @PostMapping("/verify-reset-otp")
    public ResponseEntity<ApiResponse<Map<String, String>>> verifyResetOtp(
            @Valid @RequestBody VerifyPasswordResetOtpRequest request,
            HttpServletRequest servletRequest) {
        String resetToken = authService.verifyPasswordResetOtp(request, servletRequest.getRemoteAddr())
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired verification code"));
        return ResponseEntity.ok(ApiResponse.success("Verification successful",
                Map.of("resetToken", resetToken)));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(ApiResponse.success("Password reset successfully.", null));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Map<String, Object>>> register(@Valid @RequestBody RegisterRequest request) {
        User user = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("User registered", Map.of("email", user.getEmail())));
    }
}
