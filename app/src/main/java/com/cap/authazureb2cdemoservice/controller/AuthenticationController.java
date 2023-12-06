package com.cap.authazureb2cdemoservice.controller;

import java.net.MalformedURLException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/")
@RequiredArgsConstructor
public class AuthenticationController {

    @GetMapping("/home")
    @ResponseBody
    public List<String> home(HttpServletRequest request) {
        return request.getParameterMap().entrySet().stream()
                .map(entry -> entry.getKey() + " " + entry.getValue().toString()).collect(Collectors.toList());
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logoutUser(HttpServletRequest request, HttpServletResponse response) {
        return ResponseEntity.ok("logout");
    }

    /*
     * @GetMapping("/tokenUser")
     * public ResponseEntity<UserResponse> getUserFromToken(HttpServletRequest
     * request) {
     * try {
     * var token = tokenService.recoverToken(request);
     * var tokenResult = tokenService.validateToken(token);//
     * URLDecoder.decode(token, "UTF-8"));
     * 
     * if (!tokenResult.isPresent())
     * return ResponseEntity.status(HttpStatus.BAD_REQUEST)
     * .body(UserResponse.ofError(tokenResult.getErrorMsg()));
     * 
     * var userId = tokenResult.get();
     * var user = userService.getUser(userId);
     * return ResponseEntity.ok(user);
     * } catch (Exception e) {
     * return
     * ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(UserResponse.
     * ofError(e.getMessage()));
     * }
     * }
     * 
     * @GetMapping("/tokenAuthorities")
     * public ResponseEntity<List<String>>
     * getAuthoritiesFromToken(HttpServletRequest request) {
     * try {
     * var token = tokenService.recoverToken(request);
     * var tokenResult = tokenService.validateToken(token);//
     * URLDecoder.decode(token, "UTF-8"));
     * 
     * if (!tokenResult.isPresent())
     * return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(List.
     * of("No Valid Token Found"));
     * 
     * var userId = tokenResult.get();
     * var authorities = userService.getAuthorities(userId);
     * 
     * return ResponseEntity.ok(authorities);
     * } catch (Exception e) {
     * return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(List.of(e.
     * getMessage()));
     * }
     * }
     */
}