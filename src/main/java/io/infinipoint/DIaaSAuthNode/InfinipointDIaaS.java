/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package io.infinipoint.DIaaSAuthNode;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.forgerock.oauth.OAuthClientConfiguration.PROVIDER;
import static org.forgerock.oauth.clients.oauth2.OAuth2Client.DATA;
import static org.forgerock.oauth.clients.oauth2.OAuth2Client.LANDING_PAGE;
import static org.forgerock.oauth.clients.oauth2.OAuth2Client.PKCE_CODE_VERIFIER;
import static org.forgerock.oauth.clients.oauth2.OAuth2Client.STATE;
import static org.forgerock.oauth.clients.oidc.OpenIDConnectClient.NONCE;
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper.DEFAULT_OAUTH2_SCOPE_DELIMITER;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.forgerock.http.Handler;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.oauth.DataStore;
import org.forgerock.oauth.OAuthClient;
import org.forgerock.oauth.OAuthClientConfiguration;
import org.forgerock.oauth.OAuthException;
import org.forgerock.oauth.UserInfo;
import org.forgerock.oauth.clients.oauth2.PkceMethod;
import org.forgerock.oauth.clients.oidc.OpenIDConnectClientConfiguration;
import org.forgerock.oauth.clients.oidc.OpenIDConnectUserInfo;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.oauth.AbstractSocialAuthLoginNode;
import org.forgerock.openam.auth.nodes.oauth.ProfileNormalizer;
import org.forgerock.openam.auth.nodes.oauth.SharedStateAdaptor;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.sm.validation.URLValidator;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.util.encode.Base64url;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.google.inject.name.Named;
import com.iplanet.am.util.SystemProperties;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.RequiredValueValidator;

@Node.Metadata(outcomeProvider = InfinipointDIaaS.InfinipointComplianceOutcomeProvider.class,
        configClass = InfinipointDIaaS.Config.class, tags = {"contextual"})
public class InfinipointDIaaS implements Node {
    static final String INFINIPOINT_AUTHORIZATION_ENDPOINT = "infinipoint_authorization_endpoint";
    static final String INFINIPOINT_TOKEN_ENDPOINT = "infinipoint_token_endpoint";
    static final String INFINIPOINT_USERINFO_ENDPOINT = "infinipoint_userinfo_endpoint";
    static final String INFINIPOINT_JWK_ENDPOINT = "infinipoint_jwk_endpoint";
    static final String INFINIPOINT_ISSUER = "infinipoint_issuer";
    static private final String INFINIPOINT_SERVER = "https://auth.infinipoint.io";
    static private final String VALID_SCOPES_STRING = "openid email";
    static private final String INFINIPOINT_PROVIDER = "infinipoint";

    private final Logger logger = LoggerFactory.getLogger(InfinipointDIaaS.class);

    private final Config config;
    private final ProfileNormalizer profileNormalizer;
    private final SocialOAuth2Helper authModuleHelper;
    private final SecureRandom random;
    private final Realm realm;
    private final Handler handler;
    private OAuthClient client;


    public interface Config {
        /**
         * the client id.
         *
         * @return the client id
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String clientId();

        /**
         * The client secret.
         *
         * @return the client secret
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        @Password
        char[] clientSecret();

        /**
         * The realm ID.
         *
         * @return the realm ID.
         */
        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        String realmId();

        /**
         * The URI the AS will redirect to.
         *
         * @return the redirect URI
         */
        @Attribute(order = 400, validators = {RequiredValueValidator.class, URLValidator.class})
        default String redirectURI() {
            return getServerURL();
        }

        @Attribute(order = 500)
        default boolean saveUserAttributesToSession() {
            return false;
        }
    }

    @Inject
    public InfinipointDIaaS(@Named("CloseableHttpClientHandler") Handler handler, @Assisted Config config,
                            SocialOAuth2Helper authModuleHelper, ProfileNormalizer profileNormalizer,
                            @Assisted Realm realm) {
        this.config = config;
        this.authModuleHelper = authModuleHelper;
        this.profileNormalizer = profileNormalizer;
        this.random = new SecureRandom();
        this.realm = realm;
        this.handler = handler;
    }

    protected static String getServerURL() {
        final String protocol = SystemProperties.get(Constants.AM_SERVER_PROTOCOL);
        final String host = SystemProperties.get(Constants.AM_SERVER_HOST);
        final String port = SystemProperties.get(Constants.AM_SERVER_PORT);
        final String descriptor = SystemProperties.get(Constants.AM_SERVICES_DEPLOYMENT_DESCRIPTOR);

        if (protocol != null && host != null && port != null && descriptor != null) {
            return protocol + "://" + host + ":" + port + descriptor;
        } else {
            return "";
        }
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        ExternalRequestContext request = context.request;
        JsonValue sharedState = context.sharedState;

        String username = sharedState.get(USERNAME).asString();
        if (StringUtils.isEmpty(username)) {
            Action.ActionBuilder action = goTo(InfinipointComplianceOutcome.USER_NOT_AUTHENTICATED.name());
            return action.build();
        }

        if (!CollectionUtils.isEmpty(request.parameters.get("error"))) {
            logger.debug("Error returned in query parameters of redirect");
            throw new NodeProcessException(String.format("%s: %s", request.parameters.get("error").get(0),
                                                         request.parameters.get("error_description").get(0)));
        } else if (!CollectionUtils.isEmpty(request.parameters.get("code"))) {
            return processOAuthTokenState(context, realm);
        }

        return handleAuthorizationRequest(context.request, sharedState);
    }

    private Action processOAuthTokenState(TreeContext context, Realm realm) throws NodeProcessException {

        Map<String, Set<String>> attributes;
        try {
            UserInfo userInfo = getUserInfo(context, realm);

            OAUTHConfig oauthConfig = new OAUTHConfig(config.clientId());
            attributes = profileNormalizer.getNormalisedAttributes(userInfo, getJwtClaims(userInfo), oauthConfig);

            Action.ActionBuilder action = goTo(InfinipointComplianceOutcome.POSTURE_APPROVED.name()).replaceSharedState(
                    context.sharedState);
            if (config.saveUserAttributesToSession()) {
                attributes.forEach((key, value) -> action.putSessionProperty(key, value.stream().findFirst().get()));
            }

            return action.build();
        } catch (AuthLoginException e) {
            throw new NodeProcessException(e);
        }
    }

    private UserInfo getUserInfo(TreeContext context, Realm realm) throws NodeProcessException {

        this.client = authModuleHelper.newOAuthClient(realm, getOAuthClientConfiguration(config, context), handler);

        DataStore dataStore = SharedStateAdaptor.toDatastore(context.sharedState);
        try {
            if (!context.request.parameters.containsKey("state")) {
                throw new NodeProcessException("Not having the state could mean that this request did not come from "
                                                       + "the IDP");
            }
            HashMap<String, List<String>> parameters = new HashMap<>();
            parameters.put("state", singletonList(context.request.parameters.get("state").get(0)));
            parameters.put("code", singletonList(context.request.parameters.get("code").get(0)));

            logger.debug("fetching the access token ...");
            return client.handlePostAuth(dataStore, parameters)
                         .thenAsync(value -> {
                             logger.debug("Fetch user info from userInfo endpoint");
                             return client.getUserInfo(dataStore);
                         }).getOrThrowUninterruptibly();
        } catch (OAuthException e) {
            throw new NodeProcessException("Unable to get UserInfo details from provider", e);
        }
    }

    private JwtClaimsSet getJwtClaims(org.forgerock.oauth.UserInfo userInfo) {
        return ((OpenIDConnectUserInfo) userInfo).getJwtClaimsSet();
    }

    private Action handleAuthorizationRequest(ExternalRequestContext request, JsonValue sharedState)
            throws NodeProcessException {

        sharedState.put(INFINIPOINT_AUTHORIZATION_ENDPOINT, getAuthEndpointURI());
        sharedState.put(INFINIPOINT_TOKEN_ENDPOINT, getTokenEndpoint());
        sharedState.put(INFINIPOINT_USERINFO_ENDPOINT, getUserInfoEndpoint());
        sharedState.put(INFINIPOINT_JWK_ENDPOINT, getJwkEndpoint());
        sharedState.put(INFINIPOINT_ISSUER, getIssuer());

        ClientInformation clientInformation = getClientInformation();

        State authRequestState = new State();
        sharedState.put("state", authRequestState.getValue());

        final String nonce = new BigInteger(160, random).toString(Character.MAX_RADIX);
        byte[] pkceVerifier = new byte[32];
        random.nextBytes(pkceVerifier);

        sharedState.put(PROVIDER, INFINIPOINT_PROVIDER);
        sharedState.put(STATE, authRequestState.getValue());
        sharedState.put(NONCE, nonce);
        sharedState.put(DATA, null);
        sharedState.put(LANDING_PAGE, null);
        sharedState.put(PKCE_CODE_VERIFIER, Base64url.encode(pkceVerifier));

        URI redirectURI;
        try {
            redirectURI = new URI(config.redirectURI());
        } catch (URISyntaxException e) {
            throw new NodeProcessException("Malformed redirect URI");
        }

        AuthenticationRequest.Builder authenticationRequestBuilder = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                Scope.parse(VALID_SCOPES_STRING), clientInformation.getID(), redirectURI)
                .endpointURI(getAuthEndpointURI())
                .state(authRequestState).nonce(new Nonce(nonce));

        authenticationRequestBuilder = authenticationRequestBuilder.customParameter("login_hint",
                                                                                    sharedState.get(USERNAME)
                                                                                               .asString());

        AuthenticationRequest authenticationRequest = authenticationRequestBuilder.build();

        RedirectCallback authenticationRequestCallback = new RedirectCallback(authenticationRequest.toURI().toString(),
                                                                              null, "GET");
        authenticationRequestCallback.setTrackingCookie(true);
        return send(authenticationRequestCallback).replaceSharedState(sharedState).build();
    }

    private OAuthClientConfiguration getOAuthClientConfiguration(Config config, TreeContext context) {
        OpenIDConnectClientConfiguration.Builder<?, OpenIDConnectClientConfiguration> builder =
                OpenIDConnectClientConfiguration.openIdConnectClientConfiguration();
        return builder.withClientId(config.clientId())
                      .withClientSecret(new String(config.clientSecret()))
                      .withAuthorizationEndpoint(context.sharedState.get(INFINIPOINT_AUTHORIZATION_ENDPOINT).asString())
                      .withTokenEndpoint(context.sharedState.get(INFINIPOINT_TOKEN_ENDPOINT).asString())
                      .withScope(Collections.singletonList(VALID_SCOPES_STRING))
                      .withScopeDelimiter(DEFAULT_OAUTH2_SCOPE_DELIMITER)
                      .withBasicAuth(true)
                      .withUserInfoEndpoint(context.sharedState.get(INFINIPOINT_USERINFO_ENDPOINT).asString())
                      .withRedirectUri(URI.create(config.redirectURI()))
                      .withProvider(INFINIPOINT_PROVIDER)
                      .withIssuer(context.sharedState.get(INFINIPOINT_ISSUER).asString())
                      .withAuthenticationIdKey("sub")
                      .withPkceMethod(PkceMethod.NONE)
                      .withJwk(context.sharedState.get(INFINIPOINT_JWK_ENDPOINT).asString())
                      .build();
    }

    private URI getAuthEndpointURI() {
        try {
            return new URI(String.format("%s/auth/realms/%s/protocol/openid-connect/auth", INFINIPOINT_SERVER,
                                         this.config.realmId()));
        } catch (URISyntaxException ignore) {
        }

        return null;
    }

    private String getTokenEndpoint() {
        return String.format("%s/auth/realms/%s/protocol/openid-connect/token", INFINIPOINT_SERVER,
                             this.config.realmId());
    }

    private String getUserInfoEndpoint() {
        return String.format("%s/auth/realms/%s/protocol/openid-connect/userinfo", INFINIPOINT_SERVER,
                             this.config.realmId());
    }

    private String getJwkEndpoint() {
        return String.format("%s/auth/realms/%s/protocol/openid-connect/certs", INFINIPOINT_SERVER,
                             this.config.realmId());
    }

    private String getIssuer() {
        return String.format("%s/auth/realms/%s", INFINIPOINT_SERVER, this.config.realmId());
    }

    /**
     * build Nimbus ClientInformation that contains the client ID and secret
     */
    private ClientInformation getClientInformation() {
        ClientMetadata clientMetadata = new ClientMetadata();
        return new ClientInformation(new ClientID(config.clientId()), new Date(), clientMetadata,
                                     new Secret(new String(config.clientSecret())));
    }

    public enum InfinipointComplianceOutcome {
        POSTURE_APPROVED,
        USER_NOT_AUTHENTICATED;

        InfinipointComplianceOutcome() {
        }
    }

    public static class InfinipointComplianceOutcomeProvider implements OutcomeProvider {
        public InfinipointComplianceOutcomeProvider() {
        }

        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            return ImmutableList.of(
                    new Outcome(InfinipointComplianceOutcome.POSTURE_APPROVED.name(), "Posture Approved"),
                    new Outcome(InfinipointComplianceOutcome.USER_NOT_AUTHENTICATED.name(), "User Not Authenticated"));
        }
    }

    public static class OAUTHConfig implements AbstractSocialAuthLoginNode.Config {

        private final String clientId;

        public OAUTHConfig(String clientId) {
            this.clientId = clientId;
        }

        public String clientId() {
            return clientId;
        }

        public String cfgAccountProviderClass() {
            return "org.forgerock.openam.authentication.modules.common.mapping.DefaultAccountProvider";
        }

        public String cfgAccountMapperClass() {
            return "org.forgerock.openam.authentication.modules.common.mapping.JsonAttributeMapper";
        }

        public Set<String> cfgAttributeMappingClasses() {
            return singleton("org.forgerock.openam.authentication.modules.common.mapping.JsonAttributeMapper");
        }

        public Map<String, String> cfgAccountMapperConfiguration() {
            return singletonMap("sub", "uid");
        }

        public Map<String, String> cfgAttributeMappingConfiguration() {
            Map<String, String> attributeMapConfiguration = new HashMap<>();
            attributeMapConfiguration.put("sub", "uuid");
            return attributeMapConfiguration;
        }

        public boolean saveUserAttributesToSession() {
            return true;
        }
    }

}
