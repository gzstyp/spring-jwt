package com.fwtai.config;

import com.fwtai.constants.SecurityConstants;
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
import java.util.List;

//权限(角色)拦截器
@Log4j2
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

    public JwtAuthorizationFilter(final AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,final HttpServletResponse response,FilterChain filterChain) throws IOException, ServletException{
        final String token = request.getHeader(SecurityConstants.TOKEN_HEADER);
        if(!StringUtils.isEmpty(token) && token.startsWith(SecurityConstants.TOKEN_PREFIX)){
            try{
                final Claims claims = ToolJwt.parserToken(token.substring(7));
                //final String username = ToolJwt.extractClaim(token,Claims::getSubject);
                final String username = claims.getSubject();
                final List<GrantedAuthority> authorities = claims.get(ConfigFile.roles,List.class);
                //final Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(SecurityConstants.JWT_SECRET.getBytes()).build().parseClaimsJws(token.replace(SecurityConstants.TOKEN_PREFIX,""));
                // = claimsJws.getBody().getSubject();
                //final List authorities = ((List<?>) claimsJws.getBody().get("rol")).stream().map(authority -> new SimpleGrantedAuthority((String) authority)).collect(Collectors.toList());
                if(username == null){
                    ToolClient.responseJson(ToolClient.createJsonFail("无效的token"),response);
                    return;
                }
                final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username,null,authorities);
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