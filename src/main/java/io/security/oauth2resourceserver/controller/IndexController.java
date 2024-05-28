package io.security.oauth2resourceserver.controller;

import io.security.oauth2resourceserver.dto.OpaqueDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class IndexController {

    @GetMapping("/")
    public OpaqueDto index(Authentication authentication, @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {

        BearerTokenAuthentication bearerTokenAuthentication = (BearerTokenAuthentication) authentication;

        Map<String, Object> tokenAttributes = bearerTokenAuthentication.getTokenAttributes();
        boolean active = (boolean) tokenAttributes.get("active");

        OpaqueDto opaqueDto = new OpaqueDto();
        opaqueDto.setActive(active);
        opaqueDto.setAuthentication(authentication);
        opaqueDto.setPrincipal(principal);


        return opaqueDto;
    }

}
