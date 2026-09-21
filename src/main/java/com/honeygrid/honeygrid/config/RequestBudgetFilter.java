package com.honeygrid.honeygrid.config;
import com.github.benmanes.caffeine.cache.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.*;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 10)
public class RequestBudgetFilter extends OncePerRequestFilter {
    private final Cache<String,AtomicInteger> requests=Caffeine.newBuilder().maximumSize(10000)
        .expireAfterWrite(Duration.ofMinutes(1)).build();
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)
            throws ServletException,IOException {
        String path=request.getRequestURI();
        boolean sensor=path.equals("/login") || path.equals("/admin-login") || path.startsWith("/trap/") || path.startsWith("/api/v1/canary/") || path.equals("/api/v1/agent/ingest");
        if(sensor && requests.get(request.getRemoteAddr(),k -> new AtomicInteger()).incrementAndGet()>120) {
            response.setHeader("Retry-After","60"); response.sendError(429); return;
        }
        if(request.getContentLengthLong()>16384) { response.sendError(413); return; }
        // JSON is bounded even when sent with chunked transfer encoding.
        if(request.getContentType()!=null && request.getContentType().toLowerCase(java.util.Locale.ROOT).contains("json")) {
            byte[] body=request.getInputStream().readNBytes(16385);
            if(body.length>16384) { response.sendError(413); return; }
            var wrapped=new HttpServletRequestWrapper(request) {
                @Override public ServletInputStream getInputStream() {
                    var input=new ByteArrayInputStream(body);
                    return new ServletInputStream() {
                        public int read() { return input.read(); }
                        public boolean isFinished() { return input.available()==0; }
                        public boolean isReady() { return true; }
                        public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
                    };
                }
                @Override public BufferedReader getReader() { return new BufferedReader(new InputStreamReader(getInputStream(),java.nio.charset.StandardCharsets.UTF_8)); }
            };
            chain.doFilter(wrapped,response); return;
        }
        chain.doFilter(request,response);
    }
}
