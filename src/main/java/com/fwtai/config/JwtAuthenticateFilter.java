package com.fwtai.config;

import com.fwtai.model.LoginDto;
import com.fwtai.tool.ToolClient;
import com.fwtai.tool.ToolJwt;
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
import java.util.List;
import java.util.stream.Collectors;

//登录拦截器
@Log4j2
public class JwtAuthenticateFilter extends UsernamePasswordAuthenticationFilter{

    private final AuthenticationManager authenticationManager;

    public JwtAuthenticateFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        setFilterProcessesUrl(ConfigFile.AUTH_LOGIN_URL);//默认是 super(new AntPathRequestMatcher("/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,HttpServletResponse response) throws AuthenticationException{
        final LoginDto loginDto = new LoginDto(request.getParameter("username"),request.getParameter("password"));
        final UsernamePasswordAuthenticationToken uToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(),loginDto.getPassword());
        return this.authenticationManager.authenticate(uToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,HttpServletResponse response,FilterChain chain,Authentication authResult) throws IOException, ServletException{
        final User user = (User) authResult.getPrincipal();
        final List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        final String token = ToolJwt.generateToken(user.getUsername(),roles);
        response.setHeader(ConfigFile.TOKEN_HEADER,ConfigFile.TOKEN_PREFIX + token);
        ToolClient.responseJson(ToolClient.createJsonSuccess(token),response);
    }

    @Override
    protected void unsuccessfulAuthentication(final HttpServletRequest request,final HttpServletResponse response,final AuthenticationException failed) throws IOException, ServletException{
        ToolClient.responseJson(ToolClient.createJsonFail("用户名或密码错误"),response);
    }
}