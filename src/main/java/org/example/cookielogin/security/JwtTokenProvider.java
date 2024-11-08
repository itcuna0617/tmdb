package org.example.cookielogin.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.MemberRole;
import org.example.cookielogin.security.dto.TokenInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
@Component
public class JwtTokenProvider {

    private final Key key;

    @Autowired
    private UserDetailsService userDetailsService;

    // 주의 : @Value는 LomBok의 것이 아니라 springframework의 것으로 import 해야 한다.
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // 유저 정보를 통해 AccessToken, RefreshToken을 생성하는 메서드
    public TokenInfo generateToken(String email, String nickname, List<MemberRole> roles){
        log.info("######################### JwtTokenProvider -> generateToken() 메서드 내부 ########################");
        // Claims 설정
        // claims : JWT payload에 저장되는 정보 단위
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("nickname", nickname);
        claims.put("roles", roles.stream().map(MemberRole::toString).collect(Collectors.toList()));

        Date now = new Date();

        // AccessToken 생성
        String accessToken = Jwts.builder()
                .setSubject(email)
                .setClaims(claims)
                .setExpiration(new Date(now.getTime() + 10 * 60 * 1000L))   // 1분
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // RefreshToken 생성
        String refreshToken = Jwts.builder()
                .setSubject(email)
                .setClaims(claims)
                .setExpiration(new Date(now.getTime() + 1000 * 60 * 60 * 24))    // 1일
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        log.info("AccessToken 생성 완료: {}", accessToken);
        log.info("RefreshToken 생성 완료: {}", refreshToken);

        return TokenInfo.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // JWT 토큰에서 인증 정보 조회
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPK(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // 토큰에서 회원 정보 추출
    public String getUserPK(String token) {
        return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().getSubject();
    }

    // 토큰에서 닉네임만 추출
    public String getUserNickname(String token) {
        return (String) Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().get("nickname");
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(key).parseClaimsJws(jwtToken);

            log.info(claims.getBody().getExpiration().toString());

            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    // 액세스 토큰 헤더 설정
    public void setHeaderAccessToken(HttpServletResponse response, String accessToken) {
        response.setHeader("authorization", "Bearer "+ accessToken);
    }
}
