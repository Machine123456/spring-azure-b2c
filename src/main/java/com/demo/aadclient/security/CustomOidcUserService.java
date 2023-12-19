package com.demo.aadclient.security;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CustomOidcUserService extends OidcUserService {

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        Set<GrantedAuthority> authorities = oidcUser.getAuthorities().stream().collect(Collectors.toSet());

        /* fetch authorities */
      
        return getUser(userRequest,oidcUser.getUserInfo(),authorities);
    }

     private OidcUser getUser(OidcUserRequest userRequest, OidcUserInfo userInfo, Set<GrantedAuthority> authorities) {
      ClientRegistration.ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
      String userNameAttributeName = providerDetails.getUserInfoEndpoint().getUserNameAttributeName();
      return StringUtils.hasText(userNameAttributeName) ? new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo, userNameAttributeName) : new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
   }
}
