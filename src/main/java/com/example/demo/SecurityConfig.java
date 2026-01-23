package com.example.demo;

import com.example.demo.jwt.AuthEntryPointJwt;
import com.example.demo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private AuthEntryPointJwt unAuthorizedHandler;
    @Autowired
    DataSource dataSource;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        Rhe below line means every Http requet to the Application must come from an authenticated logged in user
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated())
                .csrf(csrf->csrf.disable());
//        Spring security will not create or use Http session every request must be authenticated independently
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(withDefaults());
//        http.httpBasic(withDefaults());
        http.exceptionHandling(exception ->
                exception.authenticationEntryPoint(unAuthorizedHandler)
        );
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        DefaultSecurityFilterChain build = http.build();
        return build;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            UserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("password"))
                    .roles("USER")
                    .build();

            userDetailsManager.createUser(user1);
            // ----- ADMIN -----
            UserDetails admin = User.withUsername("admin")
                    .password(passwordEncoder().encode("admin"))
                    .roles("ADMIN")
                    .build();
            userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration buider) {
        return buider.getAuthenticationManager();
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
