package com.popularsafi.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig{

    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    ///private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private UserDetailsService jwtUserDetailsService;
    ///private final UserDetailsService jwtUserDetailsService;
    private JwtRequestFilter jwtRequestFilter;
    ///private final JwtRequestFilter jwtRequestFilter;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception{
        /*httpSecurity
                //.csrf().disable()
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req -> req
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/mail/**").permitAll()
                        .anyRequest().authenticated())
                //.httpBasic().and()
                .httpBasic(Customizer.withDefaults())
                .exceptionHandling(e -> e.authenticationEntryPoint(jwtAuthenticationEntryPoint)) //.authenticationEntryPoint(jwtAuthenticationEntryPoint).and()
                .formLogin(AbstractHttpConfigurer::disable) //formLogin().disable() //formLogin(e-> e.disable());
                .sessionManagement(Customizer.withDefaults());

        //Lista de cambios deprecated -> https://docs.spring.io/spring-security/site/docs/current/api/deprecated-list.html

        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
*/
        httpSecurity
                /*.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/", "/home").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();*/
                ///.authorizeRequests().anyRequest().permitAll()

                .authorizeRequests(authorizeRequests ->
                    authorizeRequests
                        .anyRequest().permitAll() // Permitir todas las solicitudes sin autenticación
                )
///                .httpBasic(withDefaults())
                ;//.authenticationManager(new CustomAuthenticationManager());

                return httpSecurity.build();
    }

}