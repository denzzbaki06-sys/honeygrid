package com.honeygrid.honeygrid.service;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;
import java.time.Duration;
@Service
public class RateLimiterService {
    private final Cache<String,Integer> counts=Caffeine.newBuilder().maximumSize(10000)
        .expireAfterWrite(Duration.ofSeconds(30)).build();
    // An observation threshold only; this service does not block traffic.
    public boolean isBlocked(String ip) { return counts.asMap().merge(ip,1,Integer::sum)>=3; }
}
