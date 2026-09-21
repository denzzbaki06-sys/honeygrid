package com.honeygrid.honeygrid.config;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;
import java.util.UUID;

@Configuration
public class SecurityConfig {
    @Bean
    UserDetailsService operators(@Value("${honeygrid.admin.username}") String username,
                                @Value("${honeygrid.admin.password:}") String configuredPassword) {
        String password = configuredPassword;
        if (password.isBlank()) {
            password = UUID.randomUUID().toString();
            LoggerFactory.getLogger(SecurityConfig.class).warn("Temporary local operator password: {}", password);
        } else if (password.length() < 16) {
            throw new IllegalArgumentException("HONEYGRID_ADMIN_PASSWORD must have at least 16 characters");
        }
        return new InMemoryUserDetailsManager(User.withUsername(username)
                .password("{bcrypt}" + new BCryptPasswordEncoder().encode(password)).roles("OPERATOR").build());
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin-login", "/trap/**", "/api/v1/canary/**", "/api/v1/agent/ingest", "/error").permitAll()
                .anyRequest().hasRole("OPERATOR"))
            .formLogin(login -> login.defaultSuccessUrl("/", true).permitAll())
            .logout(logout -> logout.logoutSuccessUrl("/login?logout"))
            .csrf(csrf -> csrf.ignoringRequestMatchers("/admin-login", "/api/v1/agent/ingest", "/ws-honeygrid/**"))
            .exceptionHandling(errors -> errors.defaultAuthenticationEntryPointFor(
                (request, response, exception) -> response.sendError(401),
                request -> request.getRequestURI().startsWith("/api/") || request.getRequestURI().startsWith("/ws-honeygrid"))
                .defaultAuthenticationEntryPointFor(new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login"),
                    request -> !request.getRequestURI().startsWith("/api/") && !request.getRequestURI().startsWith("/ws-honeygrid")));
        http.headers(headers -> headers.contentSecurityPolicy(policy -> policy.policyDirectives(
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            + "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
            + "img-src 'self' data: https://unpkg.com; connect-src 'self'; object-src 'none'; "
            + "base-uri 'self'; frame-ancestors 'none'; form-action 'self'")));
        return http.build();
    }

    @RestController
    static class SessionController {
        @GetMapping("/api/session/csrf")
        public Map<String, String> csrf(CsrfToken token) {
            return Map.of("token", token.getToken(), "headerName", token.getHeaderName());
        }
    }
}
