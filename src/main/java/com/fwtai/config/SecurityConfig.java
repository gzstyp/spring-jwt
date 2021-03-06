package com.fwtai.config;

import com.fwtai.respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.util.Arrays;
import java.util.List;

@EnableWebSecurity
//开启权限注解
@EnableGlobalMethodSecurity(prePostEnabled = true)//注意注解的区别 https://blog.csdn.net/weixin_39220472/article/details/80873268
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserRepository userRepository;//有值,可以在configure(final AuthenticationManagerBuilder auth)实现登录认证

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/guest","/api/register").permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic()
            .and()
            .addFilter(new JwtAuthenticateFilter(authenticationManager()))//登录拦截器
            .addFilter(new JwtAuthorizationFilter(authenticationManager()))//权限(角色)拦截器
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
          .and()
          .authorizeRequests()
          // 自定义accessDecisionManager
          .accessDecisionManager(accessDecisionManager());
    }

    /*
    //这里也可以实现登录认证的(多种认证方式之一)
    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception{

    }*/

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //实现动态配置url权限
    @Bean
    public AccessDecisionManager accessDecisionManager(){
        final List<AccessDecisionVoter<? extends Object>> decisionVoters = Arrays.asList(new WebExpressionVoter(),
          // new RoleVoter(),
          new RoleBasedVoter(),new AuthenticatedVoter());
        return new UnanimousBased(decisionVoters);
    }
}