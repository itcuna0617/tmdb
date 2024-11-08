package org.example.cookielogin.security.service;

import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.Member;
import org.example.cookielogin.member.MemberRepository;
import org.example.cookielogin.member.MemberRole;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Log4j2
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    public CustomOAuth2UserService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oauth2User = super.loadUser(userRequest);
        log.info("oAuth2User: {}", oauth2User);
        final Map<String, Object> attributes = oauth2User.getAttributes();
        final String oauthId = String.valueOf(attributes.get("id"));
        final String oauthType = userRequest.getClientRegistration().getRegistrationId();

        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_GUEST"));
        if (memberRepository.findByOauthIdAndOauthType(oauthId, oauthType) != null) {
            // 로그인 ROLE_USER
            authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
            return new DefaultOAuth2User(authorities, attributes, "id");
        }
        // ROLE_GUEST
        Member member = new Member();
        member.setEmail((String)attributes.get("account_email"));
        member.setNickname((String)attributes.get("profile_nickname"));
        member.setProfileImage((String)attributes.get("profile_image"));
        member.addRole(MemberRole.USER); // 기본 권한 설정
//        memberRepository.save(member); // 신규 사용자 저장

        authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));

        return new DefaultOAuth2User(authorities, attributes, "id");

    }
}
