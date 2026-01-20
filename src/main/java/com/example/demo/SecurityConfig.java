package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    DataSource dataSource;
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
//        Rhe below line means every Http requet to the Application must come from an authenticated logged in user
        http.authorizeHttpRequests((requests)->requests.anyRequest().authenticated());
//        Spring security will not create or use Http session every request must be authenticated independently
        http.sessionManagement(session ->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        DefaultSecurityFilterChain build = http.build();
        return build;
    }
    @Bean
    public UserDetailsService userDetailsService(){
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        if (!userDetailsManager.userExists("user1")) {
        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();

            userDetailsManager.createUser(user1);
        }
        // ----- ADMIN -----
        if (!userDetailsManager.userExists("admin")) {
            UserDetails admin = User.withUsername("admin")
                    .password(passwordEncoder().encode("admin"))
                    .roles("ADMIN")
                    .build();

            userDetailsManager.createUser(admin);
        }//        return new InMemoryUserDetailsManager(user1,admin);
        return userDetailsManager;
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
//Spring Boot Start
//   |
//           |--> SecurityFilterChain needs UserDetailsService
//   |        |
//           |        --> userDetailsService() CALLED  (1) called once
//        |
//        |--> AuthenticationProvider setup needs UserDetailsService
//            |
//                    --> userDetailsService.loadByUsername() is called many times
