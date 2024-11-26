package com.apec.pos.unitl;

import java.util.List;

import com.apec.pos.PosApplication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

import com.apec.pos.entity.AccountEntity;
import com.apec.pos.repository.AccountRepository;
import com.apec.pos.service.JwtService;


@EnableWebSocketMessageBroker
@Configuration
public class SocketConfig implements WebSocketMessageBrokerConfigurer {


    @Autowired
    private JwtService jwtService;

    @Autowired
    private AccountRepository accountRepository;

    @Override
    @CrossOrigin
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws-iotfood").setAllowedOrigins(
                "http://127.0.0.1:5500",
                "https://thangdev.online",
                "http://127.0.0.1:5500",
                    "http://192.168.163.128:3000",
            "http://128.199.208.76:3000",
            "http://128.199.208.76:3001",
            "http://128.199.208.76:3002",
                        "http://localhost:3000",
            "http://14.225.204.101:3000",
            "http://14.225.204.101:3001",
                        "http://localhost:3001",
                    "https://food.labtlu.shop/",
                        "https://admin.food.labtlu.shop/",
                        "http://14.225.206.173:8081")
                .withSockJS();
    }

//    @Override
//    public void configureMessageBroker(MessageBrokerRegistry config) {
//        config.enableSimpleBroker("/topic");
//        config.setApplicationDestinationPrefixes("/app");
//    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(new ChannelInterceptor() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                StompHeaderAccessor accessor =
                        MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

                if (StompCommand.CONNECT.equals(accessor.getCommand())) {
                    List<String> authorization = accessor.getNativeHeader("Authorization");
                    String accessToken = authorization.get(0).substring(7);
                    System.out.println(accessToken);
                    AccountEntity accountEntity = accountRepository.findByUsername(jwtService.getUsernameFromToken(accessToken));
                    if (jwtService.validateToken(accessToken, accountEntity)) {
                        return message;
                    }
                    throw new MyCustomException("tài khoản không hợp lệ");
                }
                return message;
            }

        });
    }

    private class MyCustomException extends RuntimeException {
        public MyCustomException(String message) {
            super(message);
        }
    }


}
