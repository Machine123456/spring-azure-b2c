package com.cap.authazureb2cdemoservice.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration {

	private final SecurityFiler securityFiler;

	@Bean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		return (request, response, authException) -> {
			System.out.println("Unauthorized request intercepted: " + request.getRequestURI());
			System.out.println("Exception: " + authException.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " + authException.getMessage());
		};
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http)
			throws Exception {
		http
				.csrf(csrf -> csrf.disable())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(securityFiler, UsernamePasswordAuthenticationFilter.class)
				.authorizeHttpRequests(requests -> requests
						.requestMatchers("/oauth2/**", "/login/**").permitAll()
						// .requestMatchers(HttpMethod.GET, "/request/**").permitAll()
						.anyRequest().authenticated())
				.oauth2Login((oauth2Login) -> oauth2Login
						.userInfoEndpoint((userInfo) -> userInfo
								.userAuthoritiesMapper(grantedAuthoritiesMapper()))
						.tokenEndpoint((token) -> token
								.accessTokenResponseClient(this::getTokenResponse)))

				.exceptionHandling(exception -> exception.defaultAuthenticationEntryPointFor(authenticationEntryPoint(),
						new AntPathRequestMatcher("/**")));
		return http.build();
	}

	private static String getParameterValue(Map<String, Object> tokenResponseParameters, String parameterName) {
		Object obj = tokenResponseParameters.get(parameterName);
		return obj != null ? obj.toString() : null;
	}

	private OAuth2AccessTokenResponse getTokenResponse(
			OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {

		OAuth2AccessTokenResponseHttpMessageConverter converter = new OAuth2AccessTokenResponseHttpMessageConverter();

		converter.setAccessTokenResponseConverter(source -> {

			// aspected: access_token , expires_in , refresh_token , scope , token_type
			// received: id_token , token_type , not_before , id_token_expires_in ,
			// profile_info , scope

			String idToken = getParameterValue(source, "id_token");

			String source_token_type = getParameterValue(source, "token_type");
			OAuth2AccessToken.TokenType tokenType = TokenType.BEARER.getValue().equalsIgnoreCase(source_token_type)
					? TokenType.BEARER
					: null;

			String source_expires_in = getParameterValue(source, "id_token_expires_in");
			long expiresIn = source_expires_in == null ? 0L : Long.parseLong(source_expires_in);

			String source_scope = getParameterValue(source, "scope");
			Set<String> scopes = source_scope == null ? Collections.emptySet()
					: new HashSet<String>(Arrays.asList(StringUtils.delimitedListToStringArray(source_scope, " ")));

			Map<String, Object> additionalParameters = new LinkedHashMap();
			Iterator var9 = source.entrySet().iterator();

			while (var9.hasNext()) {
				Map.Entry<String, Object> entry = (Map.Entry) var9.next();
				if (!List.of("access_token","expires_in","scope","token_type").contains(entry.getKey())) {
					additionalParameters.put((String) entry.getKey(), entry.getValue());
				}
			}

			return OAuth2AccessTokenResponse
					.withToken(idToken)
					.tokenType(tokenType)
					.expiresIn(expiresIn)
					.scopes(scopes)
					//.refreshToken(refreshToken)
					.additionalParameters(additionalParameters)
					.build();

			/*
			 * var response = OAuth2AccessTokenResponse
			 * .withToken(source.get("id_token").toString())
			 * .scopes(Set.of(source.get("scope").toString()))
			 * .expiresIn(Long.parseLong(source.get("not_before").toString()))
			 * .additionalParameters(Map.of("id_token", source.get("id_token").toString()))
			 * .build();
			 */
		});

		RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(), converter));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

		DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
		client.setRestOperations(restTemplate);

		OAuth2AccessTokenResponse response = client.getTokenResponse(authorizationCodeGrantRequest);

		System.out.println("OIOIOIO");
		System.out.println("Access Token: " + response.getAccessToken());
		System.out.println("Refresh Token: " + response.getRefreshToken());
		System.out.println("Aditional Params: " + response.getAdditionalParameters());

		return response;
	}

	private GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
		return (authorities) -> {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			authorities.forEach((authority) -> {
				GrantedAuthority mappedAuthority;

				if (authority instanceof OidcUserAuthority) {
					OidcUserAuthority userAuthority = (OidcUserAuthority) authority;
					mappedAuthority = new OidcUserAuthority(
							"OIDC_USER", userAuthority.getIdToken(), userAuthority.getUserInfo());
				} else if (authority instanceof OAuth2UserAuthority) {
					OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) authority;
					mappedAuthority = new OAuth2UserAuthority(
							"OAUTH2_USER", userAuthority.getAttributes());
				} else {
					mappedAuthority = authority;
				}

				mappedAuthorities.add(mappedAuthority);
			});

			return mappedAuthorities;
		};
	}

}