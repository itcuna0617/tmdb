package org.example.cookielogin.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.Member;
import org.example.cookielogin.member.MemberRepository;
import org.example.cookielogin.member.MemberRole;
import org.example.cookielogin.security.dto.TokenInfo;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@Log4j2
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtTokenProvider tokenProvider;
    private final MemberRepository memberRepository;

    public OAuth2SuccessHandler(JwtTokenProvider tokenProvider, MemberRepository memberRepository) {
        this.tokenProvider = tokenProvider;
        this.memberRepository = memberRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // 여기에 로그인 성공 후 처리할 내용을 작성하기!
        DefaultOAuth2User oAuth2User = (DefaultOAuth2User) authentication.getPrincipal();
        log.info("authentication : " + authentication);

        if (isUser(oAuth2User)) {

        String userId = authentication.getName();
        String email = (String) ((Map)oAuth2User.getAttributes().get("kakao_account")).get("email");
        String nickname = (String) ((Map)((Map)oAuth2User.getAttributes().get("kakao_account")).get("profile")).get("nickname");
        String profileImage = (String) ((Map)oAuth2User.getAttributes().get("properties")).get("profile_image");

        log.info("userId = " + userId);
        log.info("email = " + email);
        log.info("nickname = " + nickname);
        log.info("profileImage = " + profileImage);

        Optional<Member> optionalMember = memberRepository.findByEmail(email);

        log.info("optionalMember = " + optionalMember);
        Member member;

        if (optionalMember.isPresent()) {
            member = optionalMember.get();
        } else{
            member = Member.builder()
                    .oauthId(userId)
                    .name(nickname)
                    .email(email)
                    .profileImage(profileImage)
                    .nickname(nickname)
                    .build();

            member.addRole(MemberRole.USER);

            memberRepository.save(member);
        }

        log.info("member = " + member);

        // JWT 토큰 생성
        TokenInfo tokenInfo = tokenProvider.generateToken(member.getEmail(), member.getName(), member.getMemberRoleList());

        String accessToken = tokenInfo.getAccessToken();
        String refreshToken = tokenInfo.getRefreshToken();

        log.info("Access token: " + tokenInfo.getAccessToken());
        log.info("Refresh token: " + tokenInfo.getRefreshToken());

        // Refresh Token을 쿠키에 저장
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);

        response.addCookie(refreshTokenCookie);
        response.setHeader("Authorization", "Bearer " + accessToken);

        response.sendRedirect("/access-user");
        } else{
            response.sendRedirect("/login");
        }
    }

    public boolean isUser(DefaultOAuth2User oAuth2User) {
        return oAuth2User.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_USER"));
    }
}
