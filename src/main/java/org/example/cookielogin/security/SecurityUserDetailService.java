package org.example.cookielogin.security;

import org.example.cookielogin.member.Member;
import org.example.cookielogin.member.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class SecurityUserDetailService implements UserDetailsService {
    // 사용자의 인증 정보를 데이터베이스에서 조회

    @Autowired
    private MemberRepository memberRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<Member> optionalMember = memberRepository.findByEmail(email);
        if(!optionalMember.isPresent()) {
            // 존재하지 않을 경우
            throw new UsernameNotFoundException(email + " 사용자 없음");
        } else{
            Member member = optionalMember.get();
            return new SecurityUser(member);
        }
    }
}
