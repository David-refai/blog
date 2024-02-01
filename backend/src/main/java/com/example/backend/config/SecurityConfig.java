package com.example.backend.config;


import com.example.backend.exception.DelegatingAuthenticationEntryPoint;
import com.example.backend.jwtUtility.JwtAuthenticationFilter;
import com.example.backend.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.util.Arrays;
import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Configuration class for security.
 *
 * @see EnableWebSecurity
 * @see SecurityFilterChain
 * @see AuthenticationManager
 * @see AuthenticationProvider
 * @see DaoAuthenticationProvider
 * @see PasswordEncoder
 * @see AuthenticationEntryPoint
 * @see DelegatingAuthenticationEntryPoint
 * @see JwtAuthenticationFilter
 * @see HandlerExceptionResolver
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final HandlerExceptionResolver handlerExceptionResolver;


    @Autowired
    public SecurityConfig(CustomUserDetailsService customUserDetailsService,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          HandlerExceptionResolver handlerExceptionResolver) {
        this.customUserDetailsService = customUserDetailsService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    //    passwordEncoder for password encryption is the process of converting a password into an unreadable string of characters
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    //    authenticationProvider is used to authenticate a user
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }


    /**
     * Configure the security filter chain.
     *
     * @param http The HttpSecurity.
     * @return The SecurityFilterChain.
     * @throws Exception If an error occurs.
     */

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {


        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors
                        .configurationSource(request -> {
                            var corsConfiguration = new CorsConfiguration();
                            corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:5173"));
                            corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
                            corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type", "Access-Control-Allow-Origin"));
                            return corsConfiguration;
                        }))
//
                .cors(AbstractHttpConfigurer::disable)

//                .csrf(csrf -> csrf
//                        .csrfTokenRepository().disable()
//                        .ignoringRequestMatchers("/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/register")
//
//
//                )

                .authorizeHttpRequests(configure -> configure

//                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/login",
//                                "/api/v1/auth/logout").permitAll()
//                        .requestMatchers(HttpMethod.POST, "/api/v1/posts/create-post").hasAnyAuthority("ROLE_ADMIN", "ROLE_USER")
//                        .requestMatchers(HttpMethod.GET, "/api/v1/posts/all", "/api/v1/posts/{id}","/api/v1/auth/login-google").permitAll()
//                        .requestMatchers(HttpMethod.GET,"/api/v1/users/all").hasAuthority("ROLE_ADMIN")
//                        .requestMatchers(HttpMethod.POST, "/api/v1/comments/create-comment/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_USER")
//                        .requestMatchers(HttpMethod.DELETE, "/api/v1/comments/delete-comment/{id}")
//                        .hasAnyAuthority("ROLE_ADMIN", "ROLE_MODERATOR")

                        .anyRequest().authenticated()
                )
                .oauth2Client(withDefaults())
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider(customUserDetailsService, passwordEncoder()))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(authenticationEntryPoint())
                )

                .httpBasic(withDefaults())
                .formLogin(withDefaults());
//                .oauth2Login(
//                        oauth2Login -> oauth2Login
//                                .loginPage("/api/v1/auth/login-google")
//                                .clientRegistrationRepository(clientRegistrationRepository())
//                                .authorizationEndpoint(
//                                        authorizationEndpointConfig -> authorizationEndpointConfig
//                                                .baseUri("/oauth2/authorize-client")
//                                ).redirectionEndpoint(
//                                redirectionEndpointConfig -> redirectionEndpointConfig
//                                        .baseUri("/login/oauth2/code/*"
//                                )
//                        )
//                );


        return http.build();
    }



    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {

        return new DelegatingAuthenticationEntryPoint(handlerExceptionResolver);
    }


    // config for cors policy
//    @Bean
//    public CorsConfiguration corsConfiguration() {
//        CorsConfiguration corsConfiguration = new CorsConfiguration();
//        corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:5173"));
//        corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
//        corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type", "Access-Control-Allow-Origin"));
//        return corsConfiguration;
//    }
}

