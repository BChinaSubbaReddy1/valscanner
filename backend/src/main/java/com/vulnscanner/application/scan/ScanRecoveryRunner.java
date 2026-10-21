package com.vulnscanner.application.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
public class ScanRecoveryRunner implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(ScanRecoveryRunner.class);

    private final ScanJobRepository scanJobRepository;

    public ScanRecoveryRunner(ScanJobRepository scanJobRepository) {
        this.scanJobRepository = scanJobRepository;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        List<ScanJob> interrupted = scanJobRepository.findByStatusIn(
                List.of(ScanStatus.QUEUED, ScanStatus.CRAWLING, ScanStatus.SCANNING, ScanStatus.RUNNING));
        for (ScanJob job : interrupted) {
            log.warn("Recovering scan {} left in non-terminal status {} across restart", job.getId(), job.getStatus());
            job.transitionTo(ScanStatus.FAILED, job.getProgress(),
                    "Scan interrupted by server restart", ScanFailureReason.EXECUTOR_UNAVAILABLE);
            scanJobRepository.save(job);
        }
    }
}
