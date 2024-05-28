package io.security.oauth2resourceserver.dto;

import lombok.Data;
import org.springframework.security.core.Authentication;

import java.security.Principal;

@Data
public class OpaqueDto {

    private boolean active;
    private Authentication authentication;
    private Object principal;
}
