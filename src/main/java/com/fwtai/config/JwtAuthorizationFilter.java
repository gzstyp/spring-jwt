package com.fwtai.config;

import com.fwtai.tool.ToolClient;
import com.fwtai.tool.ToolJwt;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
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
@Log4j2
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
                // 第2个参数是数据库加密的密码(如果报错可能是不需要加密的密码),但是这个密码是如何实现动态呢???可以使用LocalThread的存值取值???
                final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username,"$2a$10$0DyIbDAjgBjatDoBYLyXW.0L7LwU7mxAs9rAZjQFSu0bPKz2mbxFe",null);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }catch(final Exception exception){
                log.warn("Request to parse JWT failed : {}",exception.getMessage());
                if(exception instanceof ExpiredJwtException){
                    ToolClient.responseJson(ToolClient.createJsonFail("token已过期"),response);
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