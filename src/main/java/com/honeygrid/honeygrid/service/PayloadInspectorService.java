package com.honeygrid.honeygrid.service;
import org.springframework.stereotype.Service;
import java.util.regex.Pattern;
@Service
public class PayloadInspectorService {
    private static final Pattern SQL=Pattern.compile("(?i)(\\b(?:SELECT\\s+.+?\\s+FROM|UNION\\s+(?:ALL\\s+)?SELECT|INSERT\\s+INTO|DELETE\\s+FROM|DROP\\s+TABLE)\\b|\\bOR\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1)");
    private static final Pattern XSS=Pattern.compile("(?i)(<script\\b|javascript\\s*:|on(?:load|error)\\s*=)");
    private static final Pattern COMMAND=Pattern.compile("(?i)(cat\\s+/etc/passwd|nc\\s+-e|/bin/(?:ba)?sh\\b|(?:wget|curl)\\s+https?://|\\bwhoami\\b|\\bid;)");
    private static final Pattern PATH=Pattern.compile("(?i)(\\.\\./\\.\\./|/etc/shadow|c:\\\\windows)");
    public String inspectPayload(String payload) {
        if(payload==null || payload.isBlank()) return "GENERAL_RECONNAISSANCE";
        if(XSS.matcher(payload).find()) return "CROSS_SITE_SCRIPTING_XSS";
        if(SQL.matcher(payload).find()) return "SQL_INJECTION";
        if(COMMAND.matcher(payload).find()) return "COMMAND_INJECTION";
        if(PATH.matcher(payload).find()) return "DIRECTORY_TRAVERSAL";
        if(payload.contains("LOGIN_ATTEMPT") || payload.contains("User:")) return "CREDENTIAL_BRUTE_FORCE";
        return "SERVICE_PROBING";
    }
}
