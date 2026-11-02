package com.vulnscanner.application.auth;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import java.time.Duration;

@Service
public class PasswordResetEmailService {
    private final ObjectProvider<JavaMailSender> mailSenderProvider;
    private final boolean enabled;
    private final String host;
    private final int port;
    private final String username;
    private final String password;
    private final String from;
    private final boolean smtpAuth;
    private final boolean startTls;
    private final boolean ssl;

    public PasswordResetEmailService(ObjectProvider<JavaMailSender> mailSenderProvider,
                                     @Value("${app.email.enabled:false}") boolean enabled,
                                     @Value("${spring.mail.host:}") String host,
                                     @Value("${spring.mail.port:587}") int port,
                                     @Value("${spring.mail.username:}") String username,
                                     @Value("${spring.mail.password:}") String password,
                                     @Value("${app.email.from:}") String from,
                                     @Value("${spring.mail.properties.mail.smtp.auth:true}") boolean smtpAuth,
                                     @Value("${spring.mail.properties.mail.smtp.starttls.enable:true}") boolean startTls,
                                     @Value("${spring.mail.properties.mail.smtp.ssl.enable:false}") boolean ssl) {
        this.mailSenderProvider = mailSenderProvider;
        this.enabled = enabled;
        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
        this.from = from;
        this.smtpAuth = smtpAuth;
        this.startTls = startTls;
        this.ssl = ssl;
    }

    public boolean isConfigured() {
        return enabled
                && host != null && !host.isBlank() && host.equals(host.trim())
                && port >= 1 && port <= 65535
                && isValidSender()
                && (!smtpAuth || (hasText(username) && hasText(password)))
                && !(startTls && ssl)
                && mailSenderProvider.getIfAvailable() != null;
    }

    public void sendOtp(String recipient, String otp) {
        if (!isConfigured()) {
            throw new IllegalStateException("Password reset email is temporarily unavailable; contact support.");
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(recipient);
        message.setSubject("Your password reset verification code");
        message.setText("Your verification code is " + otp
                + ". It expires in 10 minutes. If you did not request a password reset, you can ignore this email.");
        mailSenderProvider.getObject().send(message);
    }

    public void sendLoginOtp(String recipient, String otp, Duration expiresIn) {
        if (!isConfigured()) {
            throw new IllegalStateException("Login verification email is temporarily unavailable; contact support.");
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(recipient);
        message.setSubject("Your sign-in verification code");
        message.setText("Your sign-in verification code is " + otp
                + ". It expires in " + Math.max(1, expiresIn.toMinutes()) + " minutes. "
                + "If you did not attempt to sign in, you can ignore this email.");
        mailSenderProvider.getObject().send(message);
    }

    private boolean isValidSender() {
        if (!hasText(from)) {
            return false;
        }
        try {
            InternetAddress[] addresses = InternetAddress.parse(from, true);
            return addresses.length == 1 && addresses[0].getAddress() != null;
        } catch (AddressException exception) {
            return false;
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
