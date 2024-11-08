package org.example.cookielogin.member;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;


@SpringBootTest
public class MemberTest {

    @Autowired
    MemberRepository memberRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    public void testInsertMemeber(){
        for(int i = 0; i < 10; i++){
            Member member = Member.builder()
                    .email("user" + i + "@example.com")
                    .password(passwordEncoder.encode("1234"))
                    .name("user" + i)
                    .build();

            member.addRole(MemberRole.USER);

            memberRepository.save(member);
        }
    }
}
