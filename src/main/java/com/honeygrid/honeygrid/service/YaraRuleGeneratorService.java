package com.honeygrid.honeygrid.service;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
@Service
public class YaraRuleGeneratorService {
    public String generateYaraRule(String ip,String category,String payload) {
        InputPolicy.ip(ip); InputPolicy.payload(payload);
        if(payload.isBlank()) return "// No payload available for YARA rule generation";
        String safeCategory=category==null ? "UNKNOWN" : category.replaceAll("[^a-zA-Z0-9_]","_");
        if(safeCategory.length()>64) safeCategory=safeCategory.substring(0,64);
        String hex=HexFormat.ofDelimiter(" ").withUpperCase().formatHex(payload.getBytes(StandardCharsets.UTF_8));
        return "rule Honeygrid_" + safeCategory + " {\n    meta:\n        source_ip = \"" + ip
            + "\"\n        description = \"Exact observed UTF-8 payload; review before deployment\"\n"
            + "    strings:\n        $observed = { " + hex + " }\n    condition:\n        $observed\n}\n";
    }
}
