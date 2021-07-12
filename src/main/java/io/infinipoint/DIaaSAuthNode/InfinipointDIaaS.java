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
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
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

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.utils.URIBuilder;
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
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.sm.validation.URLValidator;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.util.encode.Base64url;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.am.util.SystemProperties;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.RequiredValueValidator;

@Node.Metadata(outcomeProvider = InfinipointDIaaS.InfinipointComplianceOutcomeProvider.class,
        configClass = InfinipointDIaaS.Config.class, tags = {"contextual"})
public class InfinipointDIaaS implements Node {
    static private final String INFINIPOINT_SERVER = "https://auth.infinipoint.io";

    static final String INFINIPOINT_AUTHORIZATION_ENDPOINT = "infinipoint_authorization_endpoint";
    static final String INFINIPOINT_TOKEN_ENDPOINT = "infinipoint_token_endpoint";
    static final String INFINIPOINT_USERINFO_ENDPOINT = "infinipoint_userinfo_endpoint";
    static final String INFINIPOINT_JWK_ENDPOINT = "infinipoint_jwk_endpoint";
    static final String INFINIPOINT_ISSUER = "infinipoint_issuer";

    static private final String VALID_SCOPES_STRING = "openid email";
    static private final String INFINIPOINT_PROVIDER = "infinipoint";

    private final Logger logger = LoggerFactory.getLogger(InfinipointDIaaS.class);

    private final Config config;
    private final ProfileNormalizer profileNormalizer;
    private final SocialOAuth2Helper authModuleHelper;
    private OAuthClient client;
    private final SecureRandom random;


    public static class InfinipointComplianceOutcomeProvider implements OutcomeProvider {
        public InfinipointComplianceOutcomeProvider() {
        }

        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            return ImmutableList.of(
                    new Outcome(InfinipointComplianceOutcome.COMPLIANT.name(), "Compliant"),
                    new Outcome(InfinipointComplianceOutcome.USER_NOT_AUTHENTICATED.name(), "User Not Authenticated"));
        }
    }

    public enum InfinipointComplianceOutcome {
        COMPLIANT,
        USER_NOT_AUTHENTICATED;

        InfinipointComplianceOutcome() {
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
    }


    @Inject
    public InfinipointDIaaS(@Assisted Config config, SocialOAuth2Helper authModuleHelper,
                            ProfileNormalizer profileNormalizer) {
        this.config = config;
        this.authModuleHelper = authModuleHelper;
        this.profileNormalizer = profileNormalizer;
        this.random = new SecureRandom();
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
            return processOAuthTokenState(context);
        }

        return handleAuthorizationRequest(context.request, sharedState);
    }

    private Action processOAuthTokenState(TreeContext context) throws NodeProcessException {

        Map<String, Set<String>> attributes;
        try {
            UserInfo userInfo = getUserInfo(context);

            OAUTHConfig oauthConfig = new OAUTHConfig(config.clientId());
            attributes = profileNormalizer.getNormalisedAttributes(userInfo, getJwtClaims(userInfo), oauthConfig);

            //TODO Is there any situation where the device isn't compliant after redirect back from Infinipoint?
            Action.ActionBuilder action = goTo(InfinipointComplianceOutcome.COMPLIANT.name()).replaceSharedState(context.sharedState);
            //TODO Attributes returned from infinipoint should be stored in sharedState for downstream nodes to consume (use the device ID to call infinipoint APIs)
            //TODO Node should have configuration boolean of whether to promote attribute to session properties for other applications to consume
            attributes.forEach((key, value) -> action.putSessionProperty(key, value.stream().findFirst().get()));

            return action.build();
        } catch (AuthLoginException e) {
            throw new NodeProcessException(e);
        }
    }

    private UserInfo getUserInfo(TreeContext context) throws NodeProcessException {

        this.client = authModuleHelper.newOAuthClient(getOAuthClientConfiguration(config, context));

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

    private String oidcProviderConfigUrl() {
        return INFINIPOINT_SERVER + "/auth/realms/" + config.realmId() + "/.well-known/openid-configuration";
    }

    //TODO Remove dynamic discovery because configuration is static
    private OIDCProviderMetadata discoverIssuer() throws NodeProcessException {
        URL providerConfigurationURL;
        try {
            providerConfigurationURL = new URIBuilder(oidcProviderConfigUrl())
                    .addParameter("client_id", config.clientId())
                    .build().toURL();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new NodeProcessException("Malformed OIDC provider config URI", e);
        }

        InputStream stream;
        try {
            stream = providerConfigurationURL.openStream();
        } catch (IOException e) {
            throw new NodeProcessException("Unable to connect to provider discovery URI", e);
        }
        String providerInfo;
        try (Scanner s = new java.util.Scanner(stream)) {
            providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
        }

        OIDCProviderMetadata providerMetadata;
        try {
            providerMetadata = OIDCProviderMetadata.parse(providerInfo);
        } catch (ParseException e) {
            throw new NodeProcessException("Unable to parse issuer discovery response: " + e.getMessage());
        }
        return providerMetadata;
    }

    private Action handleAuthorizationRequest(ExternalRequestContext request, JsonValue sharedState)
            throws NodeProcessException {

        //TODO URLs should be statically defined in configuration to save round trip call per user authentication
        OIDCProviderMetadata providerMetadata = discoverIssuer();
        sharedState.put(INFINIPOINT_AUTHORIZATION_ENDPOINT, providerMetadata.getAuthorizationEndpointURI());
        sharedState.put(INFINIPOINT_TOKEN_ENDPOINT, providerMetadata.getTokenEndpointURI());
        sharedState.put(INFINIPOINT_USERINFO_ENDPOINT, providerMetadata.getUserInfoEndpointURI());
        sharedState.put(INFINIPOINT_JWK_ENDPOINT, providerMetadata.getJWKSetURI().toString());
        sharedState.put(INFINIPOINT_ISSUER, providerMetadata.getIssuer().toString());

        ClientInformation clientInformation = getClientInformation();

        State authRequestState = new State();
        sharedState.put("state", authRequestState.getValue());

        //TODO No need to add PKCEVerifier while also using client secret
        final String nonce = new BigInteger(160, random).toString(Character.MAX_RADIX);
        byte[] pkceVerifier = new byte[32];
        random.nextBytes(pkceVerifier);

        final JsonValue authRequestDetails = json(object(
                field(PROVIDER, INFINIPOINT_PROVIDER),
                field(STATE, authRequestState.getValue()),
                field(NONCE, nonce),
                field(DATA, null),
                field(LANDING_PAGE, null),
                field(PKCE_CODE_VERIFIER, Base64url.encode(pkceVerifier))));

        //TODO Why is sharedState being converted to Datastore then back to JsonValue? Instead just add authRequestDetails to sharedState
        DataStore dataStore = SharedStateAdaptor.toDatastore(json(sharedState));
        try {
            dataStore.storeData(authRequestDetails);
        } catch (OAuthException e) {
            throw new NodeProcessException(e);
        }
        sharedState = SharedStateAdaptor.fromDatastore(dataStore);

        URI redirectURI;
        try {
            redirectURI = new URI(config.redirectURI());
        } catch (URISyntaxException e) {
            throw new NodeProcessException("Malformed redirect URI");
        }

        //TODO AuthenticationRequest.Builder uses effective scopes while the OpenIDConnectClientConfiguration uses VALID_SCOPES_STRING
        Scope effectiveScopes = providerMetadata.getScopes();
        effectiveScopes.retainAll(Scope.parse(VALID_SCOPES_STRING));

        AuthenticationRequest.Builder authenticationRequestBuilder = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                effectiveScopes, clientInformation.getID(), redirectURI)
                .endpointURI(providerMetadata.getAuthorizationEndpointURI())
                .state(authRequestState).nonce(new Nonce(nonce));

        authenticationRequestBuilder = authenticationRequestBuilder.customParameter("login_hint",
                                                                                    sharedState.get(USERNAME)
                                                                                               .asString());

        AuthenticationRequest authenticationRequest = authenticationRequestBuilder.build();

        RedirectCallback authenticationRequestCallback = new RedirectCallback(authenticationRequest.toURI().toString(), null, "GET");
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


    /**
     * build Nimbus ClientInformation that contains the client ID and secret
     */
    private ClientInformation getClientInformation() {
        ClientMetadata clientMetadata = new ClientMetadata();
        return new ClientInformation(new ClientID(config.clientId()), new Date(), clientMetadata,
                new Secret(new String(config.clientSecret())));
    }

}
