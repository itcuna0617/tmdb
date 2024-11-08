package org.example.cookielogin.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class TokenInfo {
    private String grantType;   // grantType은 JWT 인증 타입으로, 여기서는 Bearer을 사용한다.(HTTP 헤더에 prefix로 붙여주는 타입이기도 함)
    private String accessToken;
    private String refreshToken;
}
