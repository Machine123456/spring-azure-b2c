package com.demo.aadclient.security;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration {

	private final CustomOidcUserService oidcUserService;

	@Bean
	public AuthenticationEntryPoint authenticationEntryPoint() {

		return (request, response, authException) -> {
			System.out.println("Unauthorized request intercepted: " +
					request.getRequestURI());
			System.out.println("Exception: " + authException.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " +
					authException.getMessage());
		};
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.csrf(csrf -> csrf.disable())
				.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
				.oauth2Login((oauth2Login) -> oauth2Login
						.userInfoEndpoint((userInfoConf) -> userInfoConf.oidcUserService(oidcUserService))
						.tokenEndpoint((tokenConf) -> tokenConf.accessTokenResponseClient(authorizationGrantRequest -> {
							OAuth2AccessTokenResponseHttpMessageConverter converter = new OAuth2AccessTokenResponseHttpMessageConverter();
							converter.setAccessTokenResponseConverter((source) -> {

								System.out.println(source);
								Map<String,Object> additionalParametersSource = new HashMap<>();
								Set<String> objParameters = Set.of("access_token", "refresh_token", "expires_in","token_type", "scope");
								for (Map.Entry<String, Object>  entry : source.entrySet()) {
									if(!objParameters.contains(entry.getKey()))
										additionalParametersSource.put(entry.getKey(), entry.getValue());
								}
								

								return OAuth2AccessTokenResponse
										.withToken(source.containsKey("access_token")? source.get("access_token").toString(): "NOT_A_TOKEN")
										.refreshToken(source.containsKey("refresh_token")? source.get("refresh_token").toString(): null)
										.expiresIn(Long.parseLong((source.containsKey("expires_in") ? source.get("expires_in") : source.get("id_token_expires_in")).toString()))
										.tokenType(TokenType.BEARER)
										.scopes(Set.of(source.get("scope").toString().split(" "))) // TODO do it better
										.additionalParameters(additionalParametersSource)
										.build();
							});
							RestTemplate restTemplate = new RestTemplate(
									Arrays.asList(new FormHttpMessageConverter(), converter));
							DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
							client.setRestOperations(restTemplate);
							return client.getTokenResponse(authorizationGrantRequest);
						})))
				.exceptionHandling(exception -> exception.defaultAuthenticationEntryPointFor(authenticationEntryPoint(),
						new AntPathRequestMatcher("/**")));

		return http.build();
	}

}