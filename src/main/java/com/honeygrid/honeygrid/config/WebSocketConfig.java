package com.honeygrid.honeygrid.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.web.socket.config.annotation.*;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
    @Override public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic");
        config.setApplicationDestinationPrefixes("/app");
    }
    @Override public void registerStompEndpoints(StompEndpointRegistry registry) {
        // No wildcard origins: browser connections must be same-origin and authenticated.
        registry.addEndpoint("/ws-honeygrid").withSockJS();
    }
    @Override public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(new OperatorSubscriptionGuard());
    }
    public static class OperatorSubscriptionGuard implements ChannelInterceptor {
        @Override public Message<?> preSend(Message<?> message, MessageChannel channel) {
            StompHeaderAccessor headers = StompHeaderAccessor.wrap(message);
            StompCommand command = headers.getCommand();
            if (command == null || command == StompCommand.DISCONNECT) return message;
            if (!(headers.getUser() instanceof Authentication auth) || !auth.isAuthenticated()
                    || auth.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ROLE_OPERATOR"))) {
                throw new AccessDeniedException("Operator session required");
            }
            if (command == StompCommand.SEND || (command == StompCommand.SUBSCRIBE
                    && !"/topic/attacks".equals(headers.getDestination()))) {
                throw new AccessDeniedException("Read-only attack subscription");
            }
            return message;
        }
    }
}
