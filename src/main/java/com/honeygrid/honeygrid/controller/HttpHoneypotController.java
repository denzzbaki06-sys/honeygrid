package com.honeygrid.honeygrid.controller;

import com.honeygrid.honeygrid.repository.AttackLogRepository;
import com.honeygrid.honeygrid.service.HoneypotService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
public class HttpHoneypotController {

    private final HoneypotService honeypotService;
    private final AttackLogRepository repository;

    public HttpHoneypotController(HoneypotService honeypotService, AttackLogRepository repository) {
        this.honeypotService = honeypotService;
        this.repository = repository;
    }

    @GetMapping("/admin-login")
    @ResponseBody
    public String renderFakeAdminPage(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        honeypotService.processAttack(clientIp, request.getLocalPort(), "HTTP_ADMIN_PAGEVIEW", "Page Accessed: /admin-login");

        return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>GATEWAY FIREWALL // SECURE ADMIN LOGIN</title>
                <style>
                    body { background: #0b0e14; color: #00f3ff; font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                    .login-card { background: rgba(18, 26, 43, 0.9); border: 1px solid #00f3ff; padding: 30px; border-radius: 8px; box-shadow: 0 0 20px rgba(0,243,255,0.2); width: 340px; }
                    h2 { margin-top: 0; text-align: center; letter-spacing: 2px; font-size: 16px; }
                    input { width: 100%; padding: 10px; margin: 8px 0; background: #050811; border: 1px solid #4a6385; color: #fff; box-sizing: border-box; }
                    button { width: 100%; padding: 10px; background: #ff0055; border: none; color: white; font-weight: bold; cursor: pointer; margin-top: 10px; }
                    button:hover { background: #d00045; }
                    .links { display: flex; justify-content: space-between; margin-top: 15px; font-size: 11px; }
                    .links a { color: #8fa3bf; text-decoration: none; }
                </style>
            </head>
            <body>
                <div class="login-card">
                    <h2>SYSTEM GATEWAY v4.2</h2>
                    <form action="/admin-login" method="POST">
                        <label>USER IDENTIFIER</label>
                        <input type="text" name="username" required placeholder="admin">
                        <label>SECRET KEY</label>
                        <input type="password" name="password" required placeholder="••••••••">
                        <button type="submit">AUTHENTICATE</button>
                    </form>
                    <div class="links">
                        <a href="#">Request Access</a>
                        <a href="#">Forgot Key?</a>
                    </div>
                </div>
            </body>
            </html>
            """;
    }

    @PostMapping("/admin-login")
    public ResponseEntity<String> handleFakeLogin(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            HttpServletRequest request) {

        String clientIp = request.getRemoteAddr();
        if (username.length() > 256 || password.length() > 1024) {
            return ResponseEntity.badRequest().body("Input too long");
        }
        String payload = "User: " + username + " | Pass: " + password;

        honeypotService.processAttack(clientIp, request.getLocalPort(), "HTTP_BRUTE_FORCE", payload);

        return ResponseEntity.status(401).body("""
            {"status": "ERROR", "code": 401, "message": "ACCESS DENIED: Credentials recorded and reported to Security Operations."}
            """);
    }

    // Top-5 Saldırgan IP'leri Dönen REST Endpoint
    @GetMapping("/api/top-attackers")
    @ResponseBody
    public List<Object[]> getTopAttackers() {
        return repository.findTopAttackers(PageRequest.of(0, 5));
    }
}