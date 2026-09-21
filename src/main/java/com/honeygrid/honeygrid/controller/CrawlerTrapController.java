package com.honeygrid.honeygrid.controller;

import com.honeygrid.honeygrid.service.HoneypotService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.UUID;

@Controller
public class CrawlerTrapController {

    private final HoneypotService honeypotService;

    public CrawlerTrapController(HoneypotService honeypotService) {
        this.honeypotService = honeypotService;
    }

    // Botları Sonsuz Dizin Döngüsüne Sokacak Tuzak Endpoint
    @GetMapping("/trap/**")
    @ResponseBody
    public String renderInfiniteTrap(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        String uri = request.getRequestURI();

        String payload = "CRAWLER_TRAP_DISCOVERED -> Bot scanning path: " + uri;
        honeypotService.processAttack(clientIp, request.getLocalPort(), "BOT_CRAWLER_TRAP", payload);

        // Rastgele üretilen 5 alt link (Botlar bunları sonsuza kadar talamaya devam eder)
        String link1 = "/trap/dir_" + UUID.randomUUID().toString().substring(0, 8);
        String link2 = "/trap/backup_" + UUID.randomUUID().toString().substring(0, 8);
        String link3 = "/trap/conf_" + UUID.randomUUID().toString().substring(0, 8);
        String link4 = "/trap/db_" + UUID.randomUUID().toString().substring(0, 8);
        String link5 = "/trap/admin_" + UUID.randomUUID().toString().substring(0, 8);

        return String.format("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>INDEX OF %s</title>
                <style>body { background:#0a0e17; color:#00ffaa; font-family:monospace; padding:20px; }</style>
            </head>
            <body>
                <h2>Directory Listing For: %s</h2>
                <hr>
                <ul>
                    <li><a href="%s">../parent_directory/</a></li>
                    <li><a href="%s">system_backup_internal.tar.gz</a></li>
                    <li><a href="%s">database_dump.sql</a></li>
                    <li><a href="%s">secrets_keys.json</a></li>
                    <li><a href="%s">admin_auth.php</a></li>
                </ul>
            </body>
            </html>
            """, "honeypot", "honeypot", link1, link2, link3, link4, link5);
    }
}