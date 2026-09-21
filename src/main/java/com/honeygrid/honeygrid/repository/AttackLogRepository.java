package com.honeygrid.honeygrid.repository;

import com.honeygrid.honeygrid.model.AttackLog;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AttackLogRepository extends JpaRepository<AttackLog, Long> {

    @org.springframework.data.jpa.repository.Modifying
    @Query("delete from AttackLog a where a.timestamp < :cutoff")
    int deleteByTimestampBefore(@org.springframework.data.repository.query.Param("cutoff") java.util.Date cutoff);

    // En çok saldıran Top-5 IP'yi ve saldırı sayılarını çekmek için özel sorgu
    @Query("SELECT a.ipAddress, COUNT(a.ipAddress) as attackCount, a.country FROM AttackLog a GROUP BY a.ipAddress, a.country ORDER BY attackCount DESC")
    List<Object[]> findTopAttackers(Pageable pageable);
}