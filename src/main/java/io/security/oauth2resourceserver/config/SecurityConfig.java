package io.security.oauth2resourceserver.config;

import com.nimbusds.jose.jwk.RSAKey;
import io.security.oauth2resourceserver.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2resourceserver.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import io.security.oauth2resourceserver.signature.RsaSecuritySigner;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {
/*
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated())
                .userDetailsService(userDetailsService())
//                .addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(jwtAuthorizationRsaPublicKeyFilter(null), UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class)
                .oauth2ResourceServer(config -> config.jwt(Customizer.withDefaults()))
        ;

        return http.build();
        */
        http
                .securityMatchers(matchers -> matchers.requestMatchers("/photos/1"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/photos/1").hasAuthority("SCOPE_photo")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(config -> config.jwt(Customizer.withDefaults()))
        ;
        return http.build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {

        http
                .securityMatchers(matchers -> matchers.requestMatchers("/photos/2"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/photos/2").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(config -> config.jwt(Customizer.withDefaults()))
        ;
        return http.build();
    }

    @Bean
    public JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicKeyFilter(JwtDecoder jwtDecoder) {
        return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
    }

//    @Bean
//    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
//        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
//    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RsaSecuritySigner rsaSecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter =
                new JwtAuthenticationFilter(rsaSecuritySigner, rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user = User.withUsername("user")
                .password("1234")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
