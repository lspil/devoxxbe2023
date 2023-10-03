package com.example.demo1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class ProjectConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.httpBasic(
            Customizer.withDefaults()
    );

    http.authorizeHttpRequests(
            c -> c.requestMatchers("/demo/**").access(new WebExpressionAuthorizationManager("isAuthenticated()"))
                    .anyRequest().authenticated()
    );

    http.csrf(
            c -> c.ignoringRequestMatchers("/some/endpoints/**")
    );

    http.cors(c -> c.configurationSource(req -> {
      CorsConfiguration conf = new CorsConfiguration();
      conf.setAllowedMethods(List.of("*"));
      return conf;
    }));

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }
}
