package org.example.cookielogin.member;

import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int memberId;
    private String oauthId;
    private String oauthType;
    private String email;        // 이메일
    private String name;         // 이름
    private String nickname;     // 별명
    private String profileImage; // 프로필 사진
    private String password;      // 비밀번호

//    @ElementCollection(fetch= FetchType.EAGER)
    @ElementCollection(fetch= FetchType.EAGER)
    @Builder.Default
    private List<MemberRole> memberRoleList = new ArrayList<>();

    public void addRole(MemberRole memberRole) {
        memberRoleList.add(memberRole);
    }

    public void clearRoles() {
        memberRoleList.clear();
    }
}
