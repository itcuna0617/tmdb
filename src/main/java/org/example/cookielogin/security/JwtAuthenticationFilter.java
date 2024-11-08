package org.example.cookielogin.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.MemberRole;
import org.example.cookielogin.security.dto.TokenInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;

    private final SecurityUserDetailService userDetailService;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        log.info("######################### JwtAuthenticationFilter -> doFilter() 메서드 내부 ########################");

        HttpServletRequest request = (HttpServletRequest) servletRequest; // HttpServletRequest로 캐스팅
        HttpServletResponse response = (HttpServletResponse) servletResponse; // HttpServletResponse로 캐스팅

        // 특정 경로에 대해서만 JWT 인증 체크
//        String path = request.getRequestURI();
//        if (isProtectedPath(path)) {

            // 1. Request Header에서 JWT 토큰 추출
            String accessToken = resolveAccessToken(request);
            String refreshToken = resolveRefreshTokenFromCookie(request);

            log.info("Access Token : " + accessToken);
            log.info("Refresh Token : " + refreshToken);

//            log.info(jwtTokenProvider.validateToken(accessToken));

            // 2. Access Token 유효성 검사
            if (accessToken != null && jwtTokenProvider.validateToken(accessToken)) {
                log.info("Access Token 검증 완료 ");
                // Access Token이 유효할 경우
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

                log.info("Authentication : " + authentication);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.info("인증된 사용자 : " + authentication.getName());
                log.info("사용자 권한 : " + authentication.getAuthorities());
            } else if (refreshToken != null && jwtTokenProvider.validateToken(refreshToken)) {
                log.info("Access Token 다시 생성해야함");
                // Access Token이 만료되고 Refresh Token이 유효한 경우
                String email = jwtTokenProvider.getUserPK(refreshToken); // Refresh Token에서 사용자 이메일 추출
                Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // 사용자 이름과 역할 리스트 가져오기 -> UserDetailsService 사용
                UserDetails userDetails = userDetailService.loadUserByUsername(email);
                String name = userDetails.getUsername();
                List<MemberRole> roles = userDetails.getAuthorities()
                        .stream()
                        .map(auth -> MemberRole.valueOf(auth.getAuthority().replace("ROLE_", ""))) // ROLE_ 제거
                        .collect(Collectors.toList());

                // 새로운 Access Token 생성
                TokenInfo newTokens = jwtTokenProvider.generateToken(email, name, roles); // 필요한 경우 이름과 역할을 전달

                // 쿠키 생성 및 설정
//            Cookie newAccessToken = new Cookie("accessToken", newTokens.getAccessToken());
//            newAccessToken.setDomain("localhost");
//            newAccessToken.setPath("/");
//            newAccessToken.setMaxAge(60 * 10); // 10분
//            newAccessToken.setSecure(true);
//            newAccessToken.setHttpOnly(true);
//            response.addCookie(newAccessToken);

                Cookie newRefreshToken = new Cookie("refreshToken", newTokens.getRefreshToken());
                newRefreshToken.setDomain("localhost");
                newRefreshToken.setPath("/");
                newRefreshToken.setMaxAge(60 * 60 * 24);   // 24시간
                newRefreshToken.setSecure(true);
                newRefreshToken.setHttpOnly(true);
                response.addCookie(newRefreshToken);

                // accessToken 헤더 설정
                jwtTokenProvider.setHeaderAccessToken(response, newTokens.getAccessToken());

                log.info("새로운 Access Token 생성 완료: " + newTokens.getAccessToken());
            }
//        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    // Cookie에서 액세스 토큰 정보 추출
//    private String resolveAccessTokenFromCookie(HttpServletRequest request) {
//        log.info("######################### JwtAuthenticationFilter -> resolveAccessTokenFromCookie() 메서드 내부 ########################");
//        Cookie[] cookies = request.getCookies();
//        if (cookies != null) {
//            for (Cookie cookie : cookies) {
//                if ("accessToken".equals(cookie.getName())) {
//                    return cookie.getValue();
//                }
//            }
//        }
//        return null;
//    }

    // 요청 헤더에서 토큰 추출
    public String resolveAccessToken(HttpServletRequest request) {
        if(request.getHeader("Authorization") != null) {
            return request.getHeader("Authorization").substring(7);
        }
        return request.getHeader("Authorization");
    }

    // Cookie에서 리프레시 토큰 정보 추출
    private String resolveRefreshTokenFromCookie(HttpServletRequest request) {
        log.info("######################### JwtAuthenticationFilter -> resolveRefreshTokenFromCookie() 메서드 내부 ########################");
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private boolean isProtectedPath(String path) {
        // 보호할 경로의 패턴을 정의
        return path.startsWith("/test/");
    }
}
