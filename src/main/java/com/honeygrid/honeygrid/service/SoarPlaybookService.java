package com.honeygrid.honeygrid.service;
import org.springframework.stereotype.Service;
import java.util.Map;
@Service
public class SoarPlaybookService {
    public Map<String, String> executeContainmentPlaybook(String ipAddress) {
        InputPolicy.ip(ipAddress);
        return Map.of("status", "NOT_IMPLEMENTED", "mode", "SIMULATION_ONLY", "targetIp", ipAddress,
            "message", "No sessions were terminated, no memory dump was captured, and no firewall or DNS rules were changed.");
    }
}
