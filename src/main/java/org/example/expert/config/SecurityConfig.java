package org.example.expert.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 * Spring Security의 핵심 설정 파일.
 * 인증 필터 등록, URL 접근 권한, 세션 정책 등을 설정.
 * */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;
    // 사용자 정보를 로드하기 위한 서비스 (Spring Security 내부적으로 사용)

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF, Form 로그인, HTTP Basic 인증 비활성화
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                // 세션 사용 안함 (Stateless, JWT 방식이기 때문)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 인증/인가 URL 설정  URL 접근 제어
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll() // 인증 없이 가능
                        .requestMatchers("/admin/**").hasAuthority("ADMIN") // OWNER 권한을 가진 사용자만 접근 가능
                        .anyRequest().authenticated() // 그 외는 인증 필요
                )
                // Security 필터 체인에 Custom Filter 등록
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}