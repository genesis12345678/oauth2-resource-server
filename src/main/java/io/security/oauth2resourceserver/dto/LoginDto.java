package io.security.oauth2resourceserver.dto;

import lombok.Data;

@Data
public class LoginDto {

    private String username;
    private String password;
}
