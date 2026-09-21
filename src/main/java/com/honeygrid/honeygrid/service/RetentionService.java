package com.honeygrid.honeygrid.service;
import com.honeygrid.honeygrid.repository.AttackLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
@Service
public class RetentionService {
    private final AttackLogRepository repository;
    private final int days;
    public RetentionService(AttackLogRepository repository,@Value("${honeygrid.retention-days:30}") int days) {
        if(days<1 || days>3650) throw new IllegalArgumentException("Retention must be between 1 and 3650 days");
        this.repository=repository;this.days=days;
    }
    @Scheduled(fixedDelay=3600000,initialDelay=60000)
    @Transactional public void expire() { repository.deleteByTimestampBefore(Date.from(Instant.now().minus(days,ChronoUnit.DAYS))); }
}
