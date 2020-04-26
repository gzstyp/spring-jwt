package com.fwtai.tool;

import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.SimpleHash;

/**
 * 密码生成密码加密数据
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2017年2月13日 下午10:31:34
 * @QQ号码 444141300
 * @官网 http://www.fwtai.com
*/
public final class ToolSHA{

    private static final String SHA1 = "SHA-1";
    /*私盐加密*/
    private final static String privateSalt = "Www.Fwtai.Com";

    /**
     * SHA-1方式密码加密,仅加密一次
     * @作者 田应平
     * @创建时间 2017年1月1日 上午10:22:54
     * @QQ号码 444141300
     * @主页 http://www.fwtai.com
    */
    private final static String encryptHash(final String object){
        return String.valueOf(new Sha256Hash(SHA1,object));
    }

    /**
     * SHA-1方式用户名密码加密,已添加盐值加密,不可逆向
     * @作者 田应平
     * @创建时间 2017年1月1日 上午10:22:37
     * @QQ号码 444141300
     * @主页 http://www.fwtai.com
    */
    public final static String encoder(final Object userName,final Object password){
        return String.valueOf(new SimpleHash(SHA1,userName,encryptHash(password+privateSalt)));
    }
}