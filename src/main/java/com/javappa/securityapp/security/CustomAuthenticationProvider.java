package com.javappa.securityapp.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;

import com.javappa.securityapp.security.domain.User;
import com.javappa.securityapp.security.repository.UserRepository;

public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication auth) {
        final User user = userRepository.findByEmail(auth.getName());
        if ((user == null)) {
            throw new BadCredentialsException("Invalid username or password");
        }

        final Authentication result = super.authenticate(auth);
        return new UsernamePasswordAuthenticationToken(user,
                                    result.getCredentials(), result.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}