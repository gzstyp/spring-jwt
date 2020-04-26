package com.fwtai.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fwtai.constants.SecurityConstants;
import com.fwtai.model.LoginDto;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

//登录拦截器
@Log4j2
public class JwtAuthenticateFilter extends UsernamePasswordAuthenticationFilter{

    private final AuthenticationManager authenticationManager;

    public JwtAuthenticateFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        setFilterProcessesUrl(SecurityConstants.AUTH_LOGIN_URL);
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,HttpServletResponse response) throws AuthenticationException{
        final LoginDto loginDto = new LoginDto(request.getParameter("username"),request.getParameter("password"));
        UsernamePasswordAuthenticationToken uToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(),loginDto.getPassword());
        return this.authenticationManager.authenticate(uToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,HttpServletResponse response,FilterChain chain,Authentication authResult) throws IOException, ServletException{
        final User user = (User) authResult.getPrincipal();
        final List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        final Key key = Keys.hmacShaKeyFor(SecurityConstants.JWT_SECRET.getBytes());
        final String token = Jwts.builder().setHeaderParam("TYP",SecurityConstants.TOKEN_TYPE).setIssuer(SecurityConstants.TOKEN_ISSUER).setAudience(SecurityConstants.TOKEN_AUDIENCE).setExpiration(new Date(System.currentTimeMillis() + 60000)).setSubject(user.getUsername()).setIssuedAt(new Date()).setSubject(user.getUsername()).claim("rol",roles).signWith(key).compact();
        response.setHeader(SecurityConstants.TOKEN_HEADER,SecurityConstants.TOKEN_PREFIX + token);
    }

    private LoginDto pareData(HttpServletRequest request) throws IOException{
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(request.getInputStream(),LoginDto.class);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,HttpServletResponse response,AuthenticationException failed) throws IOException, ServletException{
        System.out.println("用户名或密码错误");
        super.unsuccessfulAuthentication(request,response,failed);
    }
}