package com.honeygrid.honeygrid.controller;

import com.honeygrid.honeygrid.service.YaraRuleGeneratorService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/advanced-cti")
public class AdvancedCtiController {

    private final YaraRuleGeneratorService yaraRuleGeneratorService;

    public AdvancedCtiController(YaraRuleGeneratorService yaraRuleGeneratorService) {
        this.yaraRuleGeneratorService = yaraRuleGeneratorService;
    }

    @GetMapping("/yara/generate")
    public ResponseEntity<String> downloadYaraRule(
            @RequestParam(defaultValue = "127.0.0.1") String ip,
            @RequestParam(defaultValue = "SQL_INJECTION") String vuln,
            @RequestParam(defaultValue = "SELECT * FROM users") String payload) {

        String yaraContent = yaraRuleGeneratorService.generateYaraRule(ip, vuln, payload);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=honeygrid_threat.yar")
                .contentType(MediaType.TEXT_PLAIN)
                .body(yaraContent);
    }

    @GetMapping("/mesh/nodes")
    public ResponseEntity<List<Map<String, Object>>> getMeshNodesStatus() {
        List<Map<String, Object>> nodes = List.of(); // No heartbeat-backed node registry exists yet.
        return ResponseEntity.ok(nodes);
    }
}