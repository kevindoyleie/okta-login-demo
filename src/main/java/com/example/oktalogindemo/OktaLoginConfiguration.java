package com.example.oktalogindemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


@EnableWebSecurity
public class OktaLoginConfiguration
{
    private final Logger logger = LoggerFactory.getLogger(OktaLoginConfiguration.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        logger.debug("Okta Login Configuration.");
        http.authorizeRequests()
                .antMatchers("/404", "/500")
                .permitAll()
                // html assets
                .antMatchers(HttpMethod.GET, "/img/**", "/styles/**", "/scripts/**")
                .permitAll()
                // MyVhi pages
                .antMatchers("/myvhi")
                .permitAll()
                // Everything else.
                .anyRequest()
                .hasRole("USER");

        http.oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/myvhi", true)
                .failureHandler(new SimpleUrlAuthenticationFailureHandler("/404"))
                .userInfoEndpoint(userInfo -> userInfo
                        .oidcUserService(this.oidcUserService())
                )
        ).sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        return http.build();
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        logger.debug("Temp: OAuth2UserService");
        final OidcUserService delegate = new OidcUserService();

        return userRequest -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            logger.debug("Temp: oidcUser - " + oidcUser);
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());
            mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            final Boolean claim = oidcUser.getClaimAsBoolean(OktaUser.ROLE_USER);
            if (claim != null && claim) {
                List<String> grantedRoles = oidcUser.getClaimAsStringList(OktaUser.ROLE_USER);
                for (String grantedRole : grantedRoles) {
                    mappedAuthorities.add(new SimpleGrantedAuthority(grantedRole));
                }
            }
            oidcUser.getUserInfo();
            return new OktaUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo(), OktaUser.USER_ID_CLAIM);
        };
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new AuthenticationProvider() {

            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException
            {
                boolean isAuthenticated = authentication.isAuthenticated();
                logger.debug("Temp: isAuthenticated: " + isAuthenticated);
                Object credentials = authentication.getCredentials();
                logger.debug("Temp: credentials: " + credentials);
                Object details = authentication.getDetails();
                logger.debug("Temp: details: " + details);
                Object principal = authentication.getPrincipal();
                logger.debug("Temp: principal: " + principal);
                Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
                for (GrantedAuthority authority: authorities) {
                    logger.debug("Temp: authority: " + authority);
                }
                return authentication;
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return false;
            }
        };
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            @Value("0oa4kyo0dbuArwXBq0x7") String clientId,
            @Value("17sdjQo9X4ECBI0r6R2AMH1CNECQVX8YupJP5a0S") String clientSecret,
            @Value("https://vhihealthcare-test.oktapreview.com/oauth2/default/v1/authorize") String signInUri,
            @Value("https://vhihealthcare-test.oktapreview.com/oauth2/default/v1/token") String tokenEndpointUri,
            @Value("https://vhihealthcare-test.oktapreview.com/oauth2/default/v1/userinfo") String userInfoEndpointUri,
            @Value("http://localhost:8080/myvhi/login/oauth2/code/okta") String redirectUri,
            @Value("https://vhihealthcare-test.oktapreview.com/oauth2/default") String issuer,
            @Value("https://vhihealthcare-test.oktapreview.com/oauth2/default/v1/keys") String jwkSetUri,
            @Value("openid,profile,MyVHI.profile") String[] scopes
    ) {
        logger.debug("Temp: client Id: " + clientId);
        logger.debug("Temp: client secret: " + clientSecret);
        logger.debug("Temp: jwk set url: " + jwkSetUri);

        ClientRegistration registration = CommonOAuth2Provider.OKTA.getBuilder("okta")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationUri(signInUri)
                .redirectUri(redirectUri)
                .tokenUri(tokenEndpointUri)
                .userInfoUri(userInfoEndpointUri)
                .issuerUri(issuer)
                .jwkSetUri(jwkSetUri)
                .scope(scopes)
                .userNameAttributeName(OktaUser.USER_ID_CLAIM)
                .build();
        return new InMemoryClientRegistrationRepository(registration);
    }
}