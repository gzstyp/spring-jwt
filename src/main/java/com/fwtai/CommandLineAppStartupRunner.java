package com.fwtai;

import com.fwtai.entity.Role;
import com.fwtai.entity.User;
import com.fwtai.respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
public class CommandLineAppStartupRunner implements CommandLineRunner {

    private static final String USERNAME="user";
    private static final String PASSWORD="123456";
    private static final String ROLE="ADMIN";

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(final String... args) throws Exception {
        final Optional<User> optionalUser = userRepository.findByName(USERNAME);
        if(!optionalUser.isPresent()){
            final User user = new User();
            user.setName(USERNAME);
            user.setPassword(passwordEncoder.encode(PASSWORD));
            Role role = new Role();
            role.setName(ROLE);
            role.setUsers(Arrays.asList(user));
            user.setRoles(Arrays.asList(role));
            userRepository.save(user);
        }
    }
}