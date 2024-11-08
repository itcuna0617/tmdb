package org.example.cookielogin.auth;

import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.cookielogin.member.*;
import org.example.cookielogin.security.JwtTokenProvider;
import org.example.cookielogin.security.SecurityUserDetailService;
import org.example.cookielogin.security.dto.TokenInfo;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Log4j2
@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final SecurityUserDetailService userDetailService;
    private final PasswordEncoder passwordEncoder;
    private final MovieRepository movieRepository;

    public Map login(Map<String, String> user, HttpServletResponse response) {
        // 사용자 인증 정보 생성
        UserDetails userDetails = userDetailService.loadUserByUsername(user.get("email"));
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, user.get("password"),
                userDetails.getAuthorities());

        // 인증 정보를 SecurityContextHolder에 설정(저장)
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 인증이 완료된 후 DB에 저장되어 있는 회원의 이메일, 비밀번호 검사
        Optional<Member> optionalMember = memberRepository.findByEmail(user.get("email"));

        Member member = optionalMember.orElseThrow(() -> new IllegalArgumentException("가입되지 않은 이메일입니다."));
        if (!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("이메일 또는 비밀번호가 일치하지 않습니다.");
        }

        log.info("로그인한 사용자: {}", member.getEmail());
        log.info("사용자 권한: {}", userDetails.getAuthorities());

        // Jwt 토큰 생성(인가)
        TokenInfo jwtToken = jwtTokenProvider.generateToken(member.getEmail(), member.getName(), member.getMemberRoleList());

        Map result = new HashMap();

        result.put("email", member.getEmail());
        result.put("name", member.getName());
        result.put("roles", member.getMemberRoleList());
        result.put("accessToken", jwtToken.getAccessToken());

        // 쿠키 생성 및 설정
//        Cookie accessToken = new Cookie("accessToken", jwtToken.getAccessToken());
//        accessToken.setDomain("localhost");
//        accessToken.setPath("/");
//        accessToken.setMaxAge(60 * 10); // 10분
//        accessToken.setSecure(true);
//        accessToken.setHttpOnly(true);
//        response.addCookie(accessToken);

        Cookie refreshToken = new Cookie("refreshToken", jwtToken.getRefreshToken());
        refreshToken.setDomain("localhost");
        refreshToken.setPath("/");
        refreshToken.setMaxAge(60 * 60 * 24);   // 24시간
        refreshToken.setSecure(true);
        refreshToken.setHttpOnly(true);
        response.addCookie(refreshToken);

//        response.setHeader("Set-Cookie", "refreshToken");

        // 쿠키를 HttpServletResponse에 추가
//        response.addCookie(accessToken);
//        response.addCookie(refreshToken);

        // ResponseEntity를 사용하여 응답 반환
//        HttpHeaders headers = new HttpHeaders();
//        headers.add(HttpHeaders.SET_COOKIE, accessToken.toString());
//        headers.add(HttpHeaders.SET_COOKIE, refreshToken.toString());

        // 응답에 상태코드 반환(리액트에서는 상태코드를 확인하여 처리)
//        return ResponseEntity.ok()
//                .headers(headers)
//                .body("로그인 성공");
        return result;
    }

    public ResponseEntity<?> handleOAuth2Login(OAuth2AuthenticationToken authentication, HttpServletResponse response) {
        OAuth2User oAuth2User = authentication.getPrincipal();

        // 사용자 정보 추출
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // 사용자 정보로 DB에 저장 또는 업데이트
        Optional<Member> optionalMember = memberRepository.findByEmail(email);
        Member member;

        if (optionalMember.isPresent()) {
            member = optionalMember.get();
        } else {
            // 신규 사용자 등록
            member = new Member();
            member.setEmail(email);
            member.setName(name);
            member.addRole(MemberRole.USER);
            // 필요한 경우 비밀번호와 역할 설정
            memberRepository.save(member);
        }

        // JWT 토큰 생성
        TokenInfo tokenInfo = jwtTokenProvider.generateToken(member.getEmail(), member.getName(), member.getMemberRoleList());

        // Refresh Token을 HttpOnly 쿠키에 저장
        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenInfo.getRefreshToken());
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(60 * 60 * 24); // 1일
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true); // HTTPS 사용 시 true로 설정
        response.addCookie(refreshTokenCookie);

        // Access Token을 응답으로 반환
        return ResponseEntity.ok(Map.of("accessToken", tokenInfo.getAccessToken()));
    }

    public JsonObject getInfo(String result) throws ParseException, IOException {
        JsonArray list = null;
        SimpleDateFormat dateFormat = new SimpleDateFormat("YYYY-MM-DD");

        log.info("서비스 시작" );
        JsonParser jsonParser = new JsonParser();
        JsonObject jsonObject = (JsonObject) jsonParser.parse(result);
        list = (JsonArray) jsonObject.get("results");
        JsonObject contents = null;

        for (int k = 0; k < list.size(); k++) {
            contents = (JsonObject) list.get(k);

            log.info(contents);

            String trailerPath = getTrailerKey(Long.parseLong(contents.get("id").toString()));

            if (trailerPath.length() == 0) {
                continue;
            }

            String ImgUrl = "https://image.tmdb.org/t/p/w200";
            String match = "[\"]";

            log.info(contents.get("vote_average").toString());

            movieRepository.save(
                    Movie.builder()
                            .movieId(Long.parseLong(contents.get("id").toString()))
                            .title(contents.get("title").toString())
                            .overview(contents.get("overview").toString())
                            .releaseDate(dateFormat.parse(contents.get("release_date").toString().replace("\"", "")))
                            .voteAverage(Double.parseDouble(contents.get("vote_average").toString()))
                            .voteCount(Integer.parseInt(contents.get("vote_count").toString()))
                            .posterPath(ImgUrl + contents.get("poster_path").toString())
                            .backdropPath(ImgUrl + contents.get("backdrop_path").toString())
                            .trailerPath(ImgUrl + trailerPath)
                            .build()
            );

        }
        return contents;
    }

    public JsonObject getDetail(String result) {
        log.info("서비스 시작" );
        JsonParser jsonParser = new JsonParser();
        JsonObject jsonObject = (JsonObject) jsonParser.parse(result);

        log.info(jsonObject);

        return jsonObject;
    }

    public String getTrailerKey(Long id) throws IOException {
        String result = "";
        String trailerURL = "https://api.themoviedb.org/3/movie/" + id + "/videos?api_key=553bd45e42f934beb423b51c1de01f4b&language=ko";

        URL url = new URL(trailerURL);

        BufferedReader bf = new BufferedReader(new InputStreamReader(url.openStream(), "UTF-8"));

        result = bf.readLine();

        JsonParser jsonParser = new JsonParser();
        JsonObject jsonObject = (JsonObject) jsonParser.parse(result);

        log.info(jsonObject.get("results"));

        // "results" 키의 값을 JsonArray로 가져오기
        JsonArray resultsArray = jsonObject.getAsJsonArray("results");
        // 빈 배열인지 확인
        if (resultsArray != null && resultsArray.size() == 0) {
            return "";
        } else {
            return resultsArray.get(0).toString();
        }

//        if(jsonObject.get("results"))
//        JsonObject trailer = jsonObject.get("results").getAsJsonObject();
//
//        return trailer.get("key").toString();
    }
}
