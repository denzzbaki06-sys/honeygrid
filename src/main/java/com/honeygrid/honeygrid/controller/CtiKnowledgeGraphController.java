package com.honeygrid.honeygrid.controller;

import com.honeygrid.honeygrid.model.AttackLog;
import com.honeygrid.honeygrid.repository.AttackLogRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
@RequestMapping("/api/v1/cti")
public class CtiKnowledgeGraphController {

    private final AttackLogRepository repository;

    public CtiKnowledgeGraphController(AttackLogRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/graph")
    public ResponseEntity<Map<String, Object>> getKnowledgeGraph() {
        List<AttackLog> logs = repository.findAll(org.springframework.data.domain.PageRequest.of(0, 1000, org.springframework.data.domain.Sort.by("id").descending())).getContent();

        List<Map<String, String>> nodes = new ArrayList<>();
        List<Map<String, String>> edges = new ArrayList<>();
        Set<String> addedNodes = new HashSet<>();

        for (AttackLog log : logs) {
            String ipNode = "IP_" + log.getIpAddress();
            String vulnNode = "VULN_" + (log.getVulnerabilityCategory() != null ? log.getVulnerabilityCategory() : "UNKNOWN");
            String intentNode = "INTENT_" + (log.getPredictedIntent() != null ? log.getPredictedIntent() : "BOT");

            if (addedNodes.add(ipNode)) {
                nodes.add(Map.of("id", ipNode, "label", log.getIpAddress(), "group", "AttackerIP"));
            }
            if (addedNodes.add(vulnNode)) {
                nodes.add(Map.of("id", vulnNode, "label", Objects.toString(log.getVulnerabilityCategory(), "UNKNOWN"), "group", "Vulnerability"));
            }
            if (addedNodes.add(intentNode)) {
                nodes.add(Map.of("id", intentNode, "label", Objects.toString(log.getPredictedIntent(), "UNKNOWN"), "group", "ThreatIntent"));
            }

            // İlişkileri (Edges) Ekle
            edges.add(Map.of("source", ipNode, "target", vulnNode, "relation", "EXPLOITS"));
            edges.add(Map.of("source", ipNode, "target", intentNode, "relation", "EXHIBITS_INTENT"));
        }

        Map<String, Object> graph = new HashMap<>();
        graph.put("limit", 1000);
        graph.put("truncated", repository.count() > 1000);
        graph.put("nodes", nodes);
        graph.put("edges", edges);

        return ResponseEntity.ok(graph);
    }
}