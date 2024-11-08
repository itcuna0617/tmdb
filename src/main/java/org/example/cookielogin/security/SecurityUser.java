package org.example.cookielogin.security;

import org.example.cookielogin.member.Member;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.stream.Collectors;

public class SecurityUser extends User {
    // Security 유저 정보 객체 생성 클래스
    // 인증된 사용자의 정보를 나타내는데 사용

    private Member member;

    public SecurityUser(Member member) {
        // memberId, password, role 전달
        super(member.getEmail(), member.getPassword(), member.getMemberRoleList().stream().map(str -> new SimpleGrantedAuthority("ROLE_" +str)).collect(Collectors.toList()));
        this.member = member;
    }

    public Member getMember() {
        return member;
    }
}
