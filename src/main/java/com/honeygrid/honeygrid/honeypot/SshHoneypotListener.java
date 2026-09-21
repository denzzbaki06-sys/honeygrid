package com.honeygrid.honeygrid.honeypot;
import com.honeygrid.honeygrid.service.HoneypotService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.net.*;
import java.util.concurrent.*;

@Component
@ConditionalOnProperty(name="honeygrid.ssh.enabled",havingValue="true",matchIfMissing=true)
public class SshHoneypotListener {
    private static final Logger log=LoggerFactory.getLogger(SshHoneypotListener.class);
    private final HoneypotService service;
    private final String address;
    private final int port;
    private ServerSocket server;
    private volatile boolean running;
    private final ExecutorService workers=new ThreadPoolExecutor(2,4,30,TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(128),new ThreadPoolExecutor.AbortPolicy());
    private Thread acceptThread;
    public SshHoneypotListener(HoneypotService service,@Value("${honeygrid.ssh.bind-address:127.0.0.1}") String address,
            @Value("${honeygrid.ssh.port:2222}") int port) { this.service=service;this.address=address;this.port=port; }
    @PostConstruct public void startListener() throws IOException {
        server=new ServerSocket();
        try { server.bind(new InetSocketAddress(address,port)); }
        catch(IOException error) { server.close(); workers.shutdownNow(); throw error; }
        running=true;
        acceptThread=new Thread(this::acceptLoop,"honeygrid-tcp-accept");
        acceptThread.setDaemon(true); acceptThread.start();
        log.info("TCP connection sensor listening on {}:{} (not a full SSH emulator)",address,server.getLocalPort());
    }
    private void acceptLoop() {
        while(running) {
            try(Socket client=server.accept()) {
                String ip=client.getInetAddress().getHostAddress();
                int observedPort=server.getLocalPort();
                try { workers.execute(() -> {
                    try { service.processAttack(ip,observedPort,"SSH_ATTEMPT","TCP connection observed; no SSH commands captured"); }
                    catch(RuntimeException error) { log.error("TCP event processing failed",error); }
                }); } catch(RejectedExecutionException error) { log.warn("TCP event queue full; event dropped"); }
            } catch(IOException error) { if(running) log.error("TCP accept failed",error); }
        }
    }
    @PreDestroy public void stopListener() throws IOException {
        running=false; if(server!=null) server.close(); workers.shutdownNow();
    }
    public int listeningPort() { return server.getLocalPort(); }
}
