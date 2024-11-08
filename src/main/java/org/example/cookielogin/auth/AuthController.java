package org.example.cookielogin.auth;

import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.example.cookielogin.member.Movie;
import org.example.cookielogin.member.MovieRepository;
import org.example.cookielogin.security.JwtTokenProvider;
import org.example.cookielogin.security.SecurityUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
@RestController
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private SecurityUserDetailService userDetailService;

    @Autowired
    private MovieRepository movieRepository;

    @PostMapping("/formLogin")
    public Map login(@RequestBody Map<String, String> user, HttpServletResponse response){
        log.info(user.get("email"));
        log.info(user.get("password"));
        return authService.login(user, response);
    }

//    @GetMapping("/login/oauth2/code/kakao")
//    public ResponseEntity<?> oauth2Login(OAuth2AuthenticationToken authentication, HttpServletResponse response) {
//        log.info("OAuth2AuthenticationToken: " + authentication);
//        // OAuth2 인증 정보로 사용자 로그인 처리
//        return authService.handleOAuth2Login(authentication, response);
//    }

//    @GetMapping("/login/oauth2/kakao")
//    public ResponseEntity<?> oauth2Login(OAuth2AuthenticationToken authentication, HttpServletResponse response) {
//
//        log.info("login 실행");
//        log.info("OAuth2AuthenticationToken: " + authentication);
//        // OAuth2 인증 정보로 사용자 로그인 처리
//        return authService.handleOAuth2Login(authentication, response);
//    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        log.info("로그아웃 실행?");
        // 현재 인증 정보를 지우고 세션을 무효화
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if(auth != null){
            new SecurityContextLogoutHandler().logout(request, response, auth);

            // 프론트 쪽에 가지고 있는 accessToken 이때 따로 삭제해주어야 할 듯
            
            // 쿠키 삭제
//            Cookie accessToken = new Cookie("accessToken", null); // 삭제할 쿠키 이름
//            accessToken.setPath("/"); // 쿠키의 경로를 설정 (모든 경로에서 삭제)
//            accessToken.setMaxAge(0); // 쿠키의 유효 기간을 0으로 설정하여 삭제
//            response.addCookie(accessToken); // 응답에 쿠키 추가

            Cookie refreshToken = new Cookie("refreshToken", null); // 삭제할 쿠키 이름
            refreshToken.setPath("/"); // 쿠키의 경로를 설정 (모든 경로에서 삭제)
            refreshToken.setMaxAge(0); // 쿠키의 유효 기간을 0으로 설정하여 삭제
            response.addCookie(refreshToken); // 응답에 쿠키 추가

            response.setHeader("Authorization", "");
        }

        return "로그아웃 완료!";
    }

    @GetMapping("/test")
    public String test(HttpServletResponse response){
        log.info(response.getHeader("Authorization"));
        if(response.getHeader("Authorization") != null){
            return response.getHeader("Authorization").substring(7);
        }
        return response.getHeader("Authorization");
    }

    @GetMapping("/access-user")
    public String access(HttpServletResponse response){
        return "로그인 성공!";
    }

    @GetMapping("/get-movie")
    public JsonObject getMovie(HttpServletResponse response){

        JsonObject json = null;

        try {

            for (int i = 1; i <= 5; i++) {
                String result = "";
                String apiURL = "https://api.themoviedb.org/3/discover/movie?api_key=" + "553bd45e42f934beb423b51c1de01f4b"
                        + "&release_date.gte=2013-01-01&watch_region=KR&language=ko&page=" + i;

                URL url = new URL(apiURL);

                BufferedReader bf;

                bf = new BufferedReader(new InputStreamReader(url.openStream(), "UTF-8"));

                result = bf.readLine();

                json = authService.getInfo(result);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return json;
    }

    @GetMapping("/movie-detail/{id}")
    public JsonObject getMovieById(@PathVariable("id") Long movieId) {
        String result = "";
        JsonObject json = null;

        try{
            String movieCrewURL = "https://api.themoviedb.org/3/movie/" + movieId + "/credits?api_key=" + "553bd45e42f934beb423b51c1de01f4b" + "&language=ko";
            URL url = new URL(movieCrewURL);

            BufferedReader bf;

            bf = new BufferedReader(new InputStreamReader(url.openStream(), "UTF-8"));

            result = bf.readLine();

            log.info("################### result : " + result);

            json = authService.getDetail(result);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return json;
    }
}
