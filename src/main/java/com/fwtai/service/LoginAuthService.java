package com.fwtai.service;

import com.fwtai.entity.User;
import com.fwtai.respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

//这里也可以实现登录认证的(多种认证方式之一)
@Service
public class LoginAuthService implements UserDetailsService{

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String username){
        final User user = userRepository.findByName(username).orElseThrow(() -> new UsernameNotFoundException("user not exit"));
        final List<GrantedAuthority> grantedAuthorityes = user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
        final UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getName(),user.getPassword(),grantedAuthorityes);
        return userDetails;
    }
}