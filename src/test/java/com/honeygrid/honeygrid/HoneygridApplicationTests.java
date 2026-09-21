package com.honeygrid.honeygrid;

import com.honeygrid.honeygrid.repository.AttackLogRepository;
import com.honeygrid.honeygrid.service.*;
import com.honeygrid.honeygrid.config.WebSocketConfig;
import com.honeygrid.honeygrid.honeypot.SshHoneypotListener;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.messaging.simp.stomp.*;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;

@SpringBootTest(properties={"honeygrid.ssh.enabled=false", "spring.datasource.url=jdbc:h2:mem:audit;DB_CLOSE_DELAY=-1",
    "honeygrid.admin.password=test-operator-password-only", "honeygrid.agent.api-key=test-agent-secret-at-least-32-characters"})
@AutoConfigureMockMvc
class HoneygridApplicationTests {
    @Autowired MockMvc mvc;
    @Autowired AttackLogRepository repository;
    @Autowired HoneypotService honeypot;
    @BeforeEach void clear() { repository.deleteAll(); }
    @Test void contextLoads() {}
    @Test void managementRequiresAuthentication() throws Exception {
        mvc.perform(get("/")).andExpect(status().is3xxRedirection());
        for(String path:List.of("/api/v1/reports/download/pdf","/api/v1/threat-intel/export/stix2","/ws-honeygrid/info"))
            mvc.perform(get(path)).andExpect(status().isUnauthorized());
    }
    @Test void operatorLoginWorks() throws Exception {
        mvc.perform(formLogin().user("operator").password("test-operator-password-only")).andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));
        mvc.perform(formLogin().user("operator").password("wrong")).andExpect(redirectedUrl("/login?error"));
    }
    @Test @WithMockUser(roles="VIEWER") void wrongRoleCannotReadReports() throws Exception {
        mvc.perform(get("/api/v1/reports/download/pdf")).andExpect(status().isForbidden());
    }
    @Test @WithMockUser(roles="OPERATOR") void operatorPostsRequireCsrf() throws Exception {
        mvc.perform(post("/api/v1/soc-ai/execute-containment").param("ip","192.0.2.5")).andExpect(status().isForbidden());
    }
    @Test @WithMockUser(roles="OPERATOR") void containmentCannotClaimSuccess() throws Exception {
        mvc.perform(post("/api/v1/soc-ai/execute-containment").with(csrf()).param("ip","192.0.2.5"))
            .andExpect(status().isNotImplemented()).andExpect(jsonPath("$.status").value("NOT_IMPLEMENTED"))
            .andExpect(jsonPath("$.memoryDumpFile").doesNotExist());
    }
    @Test @WithMockUser(roles="OPERATOR") void csrfTokenIsAvailable() throws Exception {
        mvc.perform(get("/api/session/csrf")).andExpect(status().isOk()).andExpect(jsonPath("$.token").isNotEmpty());
    }
    @Test void agentRequiresConfiguredSecret() throws Exception {
        mvc.perform(post("/api/v1/agent/ingest").contentType(MediaType.APPLICATION_JSON).content(telemetry("192.0.2.5","hello")))
            .andExpect(status().isUnauthorized());
        assertEquals(0,repository.count());
    }
    @Test void agentAcceptsValidTelemetry() throws Exception {
        mvc.perform(post("/api/v1/agent/ingest").header("X-Agent-API-Key","test-agent-secret-at-least-32-characters")
            .contentType(MediaType.APPLICATION_JSON).content(telemetry("2001:db8::5","hello"))).andExpect(status().isOk());
        assertEquals(1,repository.count());
    }
    @Test void agentRejectsInvalidIpAndOversizedPayload() throws Exception {
        for(String body:List.of(telemetry("example.com","hello"),telemetry("192.0.2.5","a".repeat(2001)),
                "{\"ipAddress\":\"192.0.2.5\",\"port\":-1,\"protocol\":\"SSH\",\"payload\":\"hello\"}")) {
            mvc.perform(post("/api/v1/agent/ingest").header("X-Agent-API-Key","test-agent-secret-at-least-32-characters")
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isBadRequest());
        }
        assertEquals(0,repository.count());
    }
    @Test void jsonRequestBudgetEnforced() throws Exception {
        mvc.perform(post("/api/v1/agent/ingest").contentType(MediaType.APPLICATION_JSON).content("a".repeat(16385)))
            .andExpect(status().isPayloadTooLarge());
    }
    @Test void publicDecoyRecordsCorrectPortWithoutLogin() throws Exception {
        mvc.perform(post("/admin-login").param("username","dropout").param("password","test")
            .with(request -> {request.setLocalPort(8082);return request;})).andExpect(status().isUnauthorized());
        var event=repository.findAll().getFirst();
        assertEquals(8082,event.getPort());
        assertEquals("CREDENTIAL_BRUTE_FORCE",event.getVulnerabilityCategory());
    }
    @Test void oversizedFormIsRejected() throws Exception {
        mvc.perform(post("/admin-login").param("username","a".repeat(257)).param("password","test"))
            .andExpect(status().isBadRequest());
        assertEquals(0,repository.count());
    }
    @Test @WithMockUser(roles="OPERATOR") void stixUsesObservedIpv6AndRequiredTimes() throws Exception {
        honeypot.processAttack("2001:db8::1",2222,"SSH_ATTEMPT","TCP observed");
        mvc.perform(get("/api/v1/threat-intel/export/stix2")).andExpect(status().isOk())
            .andExpect(jsonPath("$.objects[0].type").value("ipv6-addr"))
            .andExpect(jsonPath("$.objects[1].type").value("observed-data"))
            .andExpect(jsonPath("$.objects[1].modified").isNotEmpty())
            .andExpect(jsonPath("$.objects[1].number_observed").value(1));
    }
    @Test @WithMockUser(roles="OPERATOR") void pdfExportWorks() throws Exception {
        mvc.perform(get("/api/v1/reports/download/pdf")).andExpect(status().isOk()).andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }
    @Test @WithMockUser(roles="OPERATOR") void noFabricatedMeshNodes() throws Exception {
        mvc.perform(get("/api/v1/advanced-cti/mesh/nodes")).andExpect(content().json("[]"));
    }
    @Test void canaryMustHaveBeenIssued() throws Exception {
        mvc.perform(get("/api/v1/canary/ping/nonexistent")).andExpect(status().isNotFound());
        String body=mvc.perform(get("/api/v1/canary/download/env-config")).andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        String url=body.lines().filter(s -> s.startsWith("CANARY_BEACON_URL=")).findFirst().orElseThrow().split("=",2)[1];
        assertEquals(8082,URI.create(url).getPort());
        mvc.perform(get(URI.create(url).getPath())).andExpect(status().isNoContent());
    }
    @Test void intelNeverInventsRansomwareAttribution() {
        var result=new DarkWebCtiService().checkDarkWebIntel("192.0.2.5");
        assertEquals(false,result.get("isThreatMatched"));assertEquals("NOT_CONFIGURED",result.get("status"));
    }
    @Test void yaraUsesUtf8Bytes() {
        String rule=new YaraRuleGeneratorService().generateYaraRule("192.0.2.5","TEST","€\n\\\"");
        assertTrue(rule.contains("E2 82 AC 0A 5C 22"));assertFalse(rule.contains("20AC"));
    }
    @Test void heuristicPatternsAndXssScoring() {
        var inspector=new PayloadInspectorService();
        assertEquals("CREDENTIAL_BRUTE_FORCE",inspector.inspectPayload("User: dropout | Pass: test"));
        assertEquals("SQL_INJECTION",inspector.inspectPayload("SELECT * FROM users"));
        assertEquals("COMMAND_INJECTION",inspector.inspectPayload("curl https://example.invalid/file"));
        String category=inspector.inspectPayload("<img src=x onerror=alert(1)>");
        assertEquals("CROSS_SITE_SCRIPTING_XSS",category);
        assertEquals("POSSIBLE_BROWSER_SCRIPT_EXECUTION",new AttackIntentAiService().analyzeAttack(category,false,"").predictedIntent);
    }
    @Test void ipValidationDoesNotAcceptHostnamesCidrsOrInvalidOctets() {
        for(String ip:List.of("localhost","192.0.2.5/24","999.1.1.1","127.1","1.2.3.4\n","fe80::1%en0"))
            assertThrows(RuntimeException.class,() -> InputPolicy.ip(ip));
        assertEquals("2001:db8::1",InputPolicy.ip("2001:db8::1"));
    }
    @Test void websocketCannotPublishForgedEvents() {
        var guard=new WebSocketConfig.OperatorSubscriptionGuard();
        var headers=StompHeaderAccessor.create(StompCommand.SEND);
        headers.setUser(new UsernamePasswordAuthenticationToken("operator","n/a",List.of(new SimpleGrantedAuthority("ROLE_OPERATOR"))));
        headers.setDestination("/topic/attacks");
        var message=MessageBuilder.createMessage(new byte[0],headers.getMessageHeaders());
        assertThrows(org.springframework.security.access.AccessDeniedException.class,() -> guard.preSend(message,null));
    }
    @Test void sshPortCollisionFailsStartup() throws Exception {
        try(var occupied=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            var sensor=new SshHoneypotListener(mock(HoneypotService.class),"127.0.0.1",occupied.getLocalPort());
            assertThrows(java.io.IOException.class,sensor::startListener);
        }
    }
    @Test void sshSurvivesEventProcessingFailure() throws Exception {
        var service=mock(HoneypotService.class);var count=new AtomicInteger();
        doAnswer(call -> {if(count.incrementAndGet()==1) throw new IllegalStateException("expected test failure"); return null;})
            .when(service).processAttack(anyString(),anyInt(),anyString(),anyString());
        var sensor=new SshHoneypotListener(service,"127.0.0.1",0);
        try {
            sensor.startListener();
            for(int i=0;i<2;i++) try(var socket=new Socket("127.0.0.1",sensor.listeningPort())) {}
            verify(service,timeout(3000).times(2)).processAttack(anyString(),anyInt(),anyString(),anyString());
        } finally { sensor.stopListener(); }
    }
    @Test void loginRateLimitRunsBeforeAuthenticationFilter() throws Exception {
        for(int i=0;i<120;i++) mvc.perform(get("/login").with(r -> {r.setRemoteAddr("192.0.2.99");return r;}))
            .andExpect(status().isOk());
        mvc.perform(get("/login").with(r -> {r.setRemoteAddr("192.0.2.99");return r;}))
            .andExpect(status().isTooManyRequests());
    }
    @Test @WithMockUser(roles="OPERATOR") void foreignOriginCannotOpenSockJsTransport() throws Exception {
        mvc.perform(post("/ws-honeygrid/000/test/xhr").header("Origin","https://untrusted.example"))
            .andExpect(status().isForbidden());
    }
    @Test void postgresUrlSelectsPostgresDriverWithoutH2Override() throws Exception {
        var properties=new org.springframework.boot.autoconfigure.jdbc.DataSourceProperties();
        properties.setUrl("jdbc:postgresql://localhost:5432/honeygrid");
        properties.afterPropertiesSet();
        assertEquals("org.postgresql.Driver",properties.determineDriverClassName());
    }
    private static String telemetry(String ip,String payload) {
        return "{\"ipAddress\":\""+ip+"\",\"port\":2222,\"protocol\":\"SSH_ATTEMPT\",\"payload\":\""+payload+"\"}";
    }
}
