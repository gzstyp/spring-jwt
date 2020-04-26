package com.example.springjwt.config;

import com.example.springjwt.constants.SecurityConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

//权限(角色)拦截器
@Log4j2
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,final HttpServletResponse response,FilterChain filterChain) throws IOException, ServletException{
        final UsernamePasswordAuthenticationToken authentication = getAuthentication(request,response);
        if(authentication == null){
            filterChain.doFilter(request,response);
            return;
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request,response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(final HttpServletRequest request,final HttpServletResponse response){
        final String token = request.getHeader(SecurityConstants.TOKEN_HEADER);
        if(!StringUtils.isEmpty(token) && token.startsWith(SecurityConstants.TOKEN_PREFIX)){
            try{
                final Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(SecurityConstants.JWT_SECRET.getBytes()).build().parseClaimsJws(token.replace(SecurityConstants.TOKEN_PREFIX,""));
                final String username = claimsJws.getBody().getSubject();
                final List authorities = ((List<?>) claimsJws.getBody().get("rol")).stream().map(authority -> new SimpleGrantedAuthority((String) authority)).collect(Collectors.toList());
                if(!StringUtils.isEmpty(username)){
                    return new UsernamePasswordAuthenticationToken(username,null,authorities);
                }
            }catch(ExpiredJwtException exception){
                log.warn("Request to parse expired JWT : {} failed : {}",token,exception.getMessage());
            }catch(UnsupportedJwtException exception){
                log.warn("Request to parse unsupported JWT : {} failed : {}",token,exception.getMessage());
            }catch(MalformedJwtException exception){
                log.warn("Request to parse invalid JWT : {} failed : {}",token,exception.getMessage());
            }catch(SignatureException exception){
                log.warn("Request to parse JWT with invalid signature : {} failed : {}",token,exception.getMessage());
            }catch(IllegalArgumentException exception){
                log.warn("Request to parse empty or null JWT : {} failed : {}",token,exception.getMessage());
            }
        }
        return null;
    }
}