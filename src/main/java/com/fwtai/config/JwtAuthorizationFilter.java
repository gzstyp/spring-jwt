package com.fwtai.config;

import com.fwtai.tool.ToolClient;
import com.fwtai.tool.ToolJwt;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

//权限(角色)拦截器
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

    public JwtAuthorizationFilter(final AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,final HttpServletResponse response,final FilterChain filterChain) throws IOException, ServletException{
        final String token = request.getHeader(ConfigFile.TOKEN_HEADER);
        if(!StringUtils.isEmpty(token) && token.startsWith(ConfigFile.TOKEN_PREFIX)){
            try{
                final Claims claims = ToolJwt.parserToken(token.substring(7));
                final String username = claims.getSubject();
                final Collection<GrantedAuthority> authorities = claims.get(ConfigFile.roles,List.class);
                if(username == null){
                    ToolClient.responseJson(ToolClient.createJsonFail("无效的token"),response);
                    return;
                }
                // 第2个参数是数据库加密的密码(如果报错可能是不需要加密的密码),但是这个密码是如何实现动态呢???可以使用看看项目(F:\IntellijProjects\web\shiro_jwt\ssjwt)的设计方式
                //final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username,"$2a$10$0DyIbDAjgBjatDoBYLyXW.0L7LwU7mxAs9rAZjQFSu0bPKz2mbxFe",null);
                final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username,null,null);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }catch(final Exception exception){
                System.err.println(exception.getMessage());
                if(exception instanceof ExpiredJwtException){
                    ToolClient.responseJson(ToolClient.createJsonFail("token已过期"),response);
                    return;
                }else if (exception instanceof LockedException) {
                    ToolClient.responseJson(ToolClient.createJsonFail("账户被锁定,登陆失败"),response);
                    return;
                } else if (exception instanceof BadCredentialsException) {
                    ToolClient.responseJson(ToolClient.createJsonFail("账户或者密码错误,登陆失败"),response);
                    return;
                } else if (exception instanceof DisabledException) {
                    ToolClient.responseJson(ToolClient.createJsonFail("账户被禁用,登陆失败"),response);
                    return;
                } else if (exception instanceof AccountExpiredException) {
                    ToolClient.responseJson(ToolClient.createJsonFail("账户已过期,登陆失败"),response);
                    return;
                } else if (exception instanceof CredentialsExpiredException) {
                    ToolClient.responseJson(ToolClient.createJsonFail("密码已过期,登陆失败"),response);
                    return;
                }else{
                    ToolClient.responseJson(ToolClient.createJsonFail("登录信息已过期,请重新登录"),response);
                    return;
                }
            }
        }
        filterChain.doFilter(request,response);
    }
}