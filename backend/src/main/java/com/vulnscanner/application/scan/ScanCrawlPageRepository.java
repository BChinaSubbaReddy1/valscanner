package com.vulnscanner.application.scan;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanCrawlPageRepository extends JpaRepository<ScanCrawlPage, Long> {
    List<ScanCrawlPage> findByScanJob_IdOrderByDepthAscUrlAsc(Long scanId);
    long countByScanJob_Id(Long scanId);
}
