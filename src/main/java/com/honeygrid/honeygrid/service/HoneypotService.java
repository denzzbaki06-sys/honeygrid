package com.honeygrid.honeygrid.service;

import com.honeygrid.honeygrid.model.AttackLog;
import com.honeygrid.honeygrid.repository.AttackLogRepository;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class HoneypotService {
    private final AttackLogRepository repository;
    private final GeoIpService geo;
    private final MitreMapperService mitre;
    private final RateLimiterService rateLimiter;
    private final PayloadInspectorService inspector;
    private final AttackIntentAiService scorer;
    private final SimpMessagingTemplate messaging;
    public HoneypotService(AttackLogRepository repository, GeoIpService geo, MitreMapperService mitre,
            RateLimiterService rateLimiter, PayloadInspectorService inspector, AttackIntentAiService scorer,
            SimpMessagingTemplate messaging) {
        this.repository=repository; this.geo=geo; this.mitre=mitre; this.rateLimiter=rateLimiter;
        this.inspector=inspector; this.scorer=scorer; this.messaging=messaging;
    }
    public void processAttack(String ipAddress,int port,String protocol,String payload) {
        InputPolicy.ip(ipAddress); InputPolicy.payload(payload);
        boolean thresholdExceeded=rateLimiter.isBlocked(ipAddress);
        var location=geo.getIpDetails(ipAddress);
        var technique=mitre.mapAttackToMitre(protocol,payload);
        String category=inspector.inspectPayload(payload);
        var score=scorer.analyzeAttack(category,thresholdExceeded,payload);
        AttackLog log=repository.save(new AttackLog(ipAddress,port,protocol,location.getCountry(),location.getCity(),
            location.getLatitude(),location.getLongitude(),payload,technique.id,technique.name,category,
            score.threatScore,score.predictedIntent,new Date()));
        Map<String,Object> event=new HashMap<>();
        event.put("id",log.getId()); event.put("ipAddress",ipAddress); event.put("port",port); event.put("protocol",protocol);
        event.put("country",location.getCountry()); event.put("city",location.getCity());
        event.put("latitude",location.getLatitude()); event.put("longitude",location.getLongitude());
        event.put("geoLocated",false); // No GeoIP provider configured: do not fabricate coordinates.
        event.put("payload",payload); event.put("mitreId",technique.id); event.put("mitreName",technique.name);
        event.put("vulnerability",category); event.put("threatScore",score.threatScore);
        event.put("predictedIntent",score.predictedIntent); event.put("thresholdExceeded",thresholdExceeded);
        event.put("isBlocked",false); event.put("analysisMode","RULE_BASED"); event.put("timestamp",log.getTimestamp());
        messaging.convertAndSend("/topic/attacks",event);
    }
}
