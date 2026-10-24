package com.vulnscanner.localrecovery;

import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.DefaultApplicationArguments;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit coverage for {@link LocalOrganizationAdminRecoveryRunner}.
 *
 * <p>The runner reads {@link System#console()} directly rather than accepting an injected
 * {@code Console}, so most of its interactive flow (prompting for and confirming three
 * passwords, then delegating to {@link LocalOrganizationAdminRecoveryService#recover}) can
 * only be exercised end-to-end from a real interactive terminal, which is also why
 * {@code LocalOrganizationAdminRecoveryService} itself is covered separately with
 * integration tests (see {@link LocalOrganizationAdminRecoveryServiceTest}) against a mocked
 * {@link Console} is not possible here without changing the production method's signature.
 *
 * <p>What this test does verify, safely and deterministically, is the one guarantee the
 * runner makes regardless of environment: when there is no interactive console attached
 * (exactly what happens when the recovery jar/application is started from an IDE "Run" button,
 * a CI job, or any other non-TTY launcher), it must fail fast with an
 * {@link IllegalStateException} and must never call into {@link LocalOrganizationAdminRecoveryService}
 * — i.e. it must abort before inspecting or changing any account.
 */
class LocalOrganizationAdminRecoveryRunnerTest {

    @Test
    void missingInteractiveConsoleAbortsBeforeInspectingOrChangingAccounts() {
        LocalOrganizationAdminRecoveryService recoveryService = mock(LocalOrganizationAdminRecoveryService.class);
        LocalOrganizationAdminRecoveryRunner runner = new LocalOrganizationAdminRecoveryRunner(recoveryService);
        ApplicationArguments args = new DefaultApplicationArguments();

        // System.console() returns null whenever stdin/stdout are not attached to a real
        // terminal (IDE run configurations, CI, piped input) - which is exactly the state
        // under which this unit test itself runs. That lets us exercise the guard clause
        // without having to fake java.io.Console, which is effectively unmockable (final,
        // no public constructor) and not worth working around in production code just for a test.
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> runner.run(args));

        assertEquals("A real interactive terminal is required; no account changes were made.",
                exception.getMessage());
        verifyNoInteractions(recoveryService);
        verify(recoveryService, never()).recover(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }
}
