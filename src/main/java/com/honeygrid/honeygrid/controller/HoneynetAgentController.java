package com.honeygrid.honeygrid.controller;

import com.honeygrid.honeygrid.service.HoneypotService;
import com.honeygrid.honeygrid.service.InputPolicy;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/agent")
public class HoneynetAgentController {
    private final HoneypotService honeypotService;
    private final String requiredApiKey;
    public HoneynetAgentController(HoneypotService service, @Value("${honeygrid.agent.api-key:}") String key) {
        this.honeypotService = service;
        this.requiredApiKey = key;
        if (!key.isEmpty() && key.length() < 32) throw new IllegalArgumentException("Agent key must have at least 32 characters");
    }
    public record Telemetry(@NotBlank @Size(max=45) String ipAddress, @Min(1) @Max(65535) int port,
            @NotBlank @Pattern(regexp="[A-Z0-9_]{1,40}") String protocol, @NotNull @Size(max=2000) String payload) {}

    @PostMapping("/ingest")
    public ResponseEntity<Map<String,String>> ingestRemoteAttack(
            @RequestHeader(value="X-Agent-API-Key", required=false) String apiKey,
            @Valid @RequestBody Telemetry event) {
        if (requiredApiKey.isBlank() || apiKey == null || !MessageDigest.isEqual(
                requiredApiKey.getBytes(StandardCharsets.UTF_8), apiKey.getBytes(StandardCharsets.UTF_8))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "INVALID_AGENT_KEY"));
        }
        honeypotService.processAttack(InputPolicy.ip(event.ipAddress()), event.port(), event.protocol(), event.payload());
        return ResponseEntity.ok(Map.of("status", "INGESTED"));
    }
}
