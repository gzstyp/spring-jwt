package com.fwtai.constants;

public final class SecurityConstants {

    public static final String AUTH_LOGIN_URL = "/api/token";
    public static final String JWT_SECRET = "1YGZJCiSuFkyw4luzkNma4VqRf4ULYMpKkQTu8CE9iD4=";
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    private SecurityConstants() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }
}