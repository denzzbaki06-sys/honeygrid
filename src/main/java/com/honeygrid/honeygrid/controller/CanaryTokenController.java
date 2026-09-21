package com.honeygrid.honeygrid.controller;
import com.honeygrid.honeygrid.service.*;
import com.github.benmanes.caffeine.cache.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.time.Duration;
import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/canary")
public class CanaryTokenController {
    private final HoneypotService service;
    private final DecoyCredentialService credentials;
    private final String baseUrl;
    private final Cache<String,Boolean> issued=Caffeine.newBuilder().maximumSize(10000).expireAfterWrite(Duration.ofHours(24)).build();
    public CanaryTokenController(HoneypotService service,DecoyCredentialService credentials,
            @Value("${honeygrid.canary.base-url:http://localhost:8082}") String baseUrl) {
        URI uri=URI.create(baseUrl);
        if(!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) || uri.getHost()==null || uri.getUserInfo()!=null
            || uri.getQuery()!=null || uri.getFragment()!=null) throw new IllegalArgumentException("Invalid canary base URL");
        this.service=service;this.credentials=credentials;this.baseUrl=baseUrl.replaceAll("/+$", "");
    }
    @GetMapping("/download/env-config")
    public ResponseEntity<String> downloadFakeEnv(HttpServletRequest request) {
        String token=UUID.randomUUID().toString(); issued.put(token,true);
        var decoys=credentials.generateDecoyCredentials(request.getRemoteAddr());
        service.processAttack(request.getRemoteAddr(),request.getLocalPort(),"CANARY_TOKEN_DOWNLOAD","Decoy configuration requested");
        String body="# HONEYGRID DECOY: all credentials are synthetic\n"
            + "AWS_ACCESS_KEY_ID="+decoys.get("AWS_ACCESS_KEY_ID")+"\n"
            + "AWS_SECRET_ACCESS_KEY="+decoys.get("AWS_SECRET_ACCESS_KEY")+"\n"
            + "DATABASE_PASSWORD="+decoys.get("DATABASE_PASSWORD")+"\n"
            + "CANARY_BEACON_URL="+baseUrl+"/api/v1/canary/ping/"+token+"\n";
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=decoy.env")
            .contentType(MediaType.TEXT_PLAIN).body(body);
    }
    @GetMapping("/ping/{tokenId}")
    public ResponseEntity<Void> handleCanaryPing(@PathVariable String tokenId,HttpServletRequest request) {
        if(issued.getIfPresent(tokenId)==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        service.processAttack(request.getRemoteAddr(),request.getLocalPort(),"CANARY_BEACON_REQUEST","Issued canary URL requested: "+tokenId);
        return ResponseEntity.noContent().build();
    }
}
