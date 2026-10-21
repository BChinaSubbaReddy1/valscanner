package com.vulnscanner.application.scan;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "scan_findings", indexes = {
        @Index(name = "idx_scan_findings_scan", columnList = "scan_job_id")
})
public class ScanFinding {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_job_id", nullable = false)
    private ScanJob scanJob;

    @Column(name = "check_type", nullable = false, length = 64)
    private String checkType;

    @Column(nullable = false, length = 16)
    private String severity;

    @Column(name = "affected_component", nullable = false, length = 2048)
    private String affectedComponent;

    @Column(nullable = false, length = 1000)
    private String evidence;

    @Column(nullable = false, length = 1000)
    private String rationale;

    @Column(nullable = false, length = 1000)
    private String remediation;

    @Column(name = "detection_source", nullable = false, length = 64)
    private String detectionSource;

    @Column(name = "verification_status", nullable = false, length = 32)
    private String verificationStatus;

    @Column(name = "detected_at", nullable = false, updatable = false)
    private Instant detectedAt = Instant.now();

    protected ScanFinding() {
    }

    public ScanFinding(ScanJob scanJob, String checkType, String severity, String affectedComponent,
                       String evidence, String rationale, String remediation,
                       String detectionSource, String verificationStatus) {
        this.scanJob = scanJob;
        this.checkType = checkType;
        this.severity = severity;
        this.affectedComponent = affectedComponent;
        this.evidence = evidence;
        this.rationale = rationale;
        this.remediation = remediation;
        this.detectionSource = detectionSource;
        this.verificationStatus = verificationStatus;
    }

    public Long getId() { return id; }
    public ScanJob getScanJob() { return scanJob; }
    public String getCheckType() { return checkType; }
    public String getSeverity() { return severity; }
    public String getAffectedComponent() { return affectedComponent; }
    public String getEvidence() { return evidence; }
    public String getRationale() { return rationale; }
    public String getRemediation() { return remediation; }
    public String getDetectionSource() { return detectionSource; }
    public String getVerificationStatus() { return verificationStatus; }
    public Instant getDetectedAt() { return detectedAt; }
}
