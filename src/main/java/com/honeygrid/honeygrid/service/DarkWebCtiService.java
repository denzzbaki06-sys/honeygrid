package com.honeygrid.honeygrid.service;
import org.springframework.stereotype.Service;
import java.util.Map;
@Service
public class DarkWebCtiService {
    public Map<String,Object> checkDarkWebIntel(String ipAddress) {
        InputPolicy.ip(ipAddress);
        return Map.of("status", "NOT_CONFIGURED", "isThreatMatched", false,
            "threatActor", "UNKNOWN", "riskLevel", "UNKNOWN",
            "leakStatus", "Not checked: no external intelligence feed is configured");
    }
}
