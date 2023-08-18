package com.popularsafi.service;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserDetaillsService {
    UserDetailsService userDetailsService();
    ///UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
