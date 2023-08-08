package com.example.SpringSecurity.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //using db here, but now use only one username by default
        //if using db, then code like be there
//        User user = userRepository.findByUsername(username);
        if(username.equals("Nafiul")){
            return new User("Nafiul","123456",new ArrayList<>());
        }else{
            throw new UsernameNotFoundException("User not found");
        }
    }
}
