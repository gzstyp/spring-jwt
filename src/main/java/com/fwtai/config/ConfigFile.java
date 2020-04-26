package com.fwtai.config;

/**
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-04-26 12:25
 * @QQ号码 444141300
 * @Email service@dwlai.com
 * @官网 http://www.fwtai.com
 */

public final class ConfigFile{

    public final static String roles = "roles";

    public static final String AUTH_LOGIN_URL = "/api/token";
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    private ConfigFile() {
        throw new IllegalStateException("不能创建静态的类示例");
    }
}