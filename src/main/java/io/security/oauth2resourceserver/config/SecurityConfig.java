package io.security.oauth2resourceserver.config;

import io.security.oauth2resourceserver.CustomOpaqueTokenIntrospector;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(Customizer.withDefaults()))
        ;
        return http.build();
    }

/*
    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties properties) {
        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = properties.getOpaquetoken();
        return new NimbusOpaqueTokenIntrospector(
                opaquetoken.getIntrospectionUri(),
                opaquetoken.getClientId(),
                opaquetoken.getClientSecret()
        );
    }
*/

    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties properties) {
        return new CustomOpaqueTokenIntrospector(properties);
    }
}
