/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This file is derived from code copied from Apache Kafka:
 *
 * clients/src/main/java/org/apache/kafka/common/security/oauthbearer/secured/OAuthBearerLoginCallbackHandler.java
 */

package io.spoud.azure.auth.certificate;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.auth.SaslExtensionsCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.kafka.common.security.oauthbearer.internals.OAuthBearerClientInitialResponse;
import org.apache.kafka.common.security.oauthbearer.internals.secured.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CertOAuthBearerLoginCallbackHandler implements AuthenticateCallbackHandler {

    public static final String CLIENT_ID_CONFIG = "clientId";
    public static final String AUTHORITY_CONFIG = "authority";
    public static final String CERT_PATH_CONFIG = "certificatePath";
    public static final String PRIVATE_KEY_PATH_CONFIG = "privateKeyPath";
    public static final String SCOPE_CONFIG = "scope";
    private static final Logger log = LoggerFactory.getLogger(CertOAuthBearerLoginCallbackHandler.class);
    private static final String EXTENSION_PREFIX = "extension_";

    private Map<String, Object> moduleOptions;

    private AccessTokenRetriever accessTokenRetriever;

    private AccessTokenValidator accessTokenValidator;

    private boolean isInitialized = false;

    @Override
    public void configure(Map<String, ?> configs, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        moduleOptions = JaasOptionsUtils.getOptions(saslMechanism, jaasConfigEntries);
        AccessTokenRetriever accessTokenRetriever = createAccessTokenRetriever(moduleOptions);
        AccessTokenValidator accessTokenValidator = AccessTokenValidatorFactory.create(configs, saslMechanism);
        init(accessTokenRetriever, accessTokenValidator);
    }

    /*
     * Package-visible for testing.
     */
    void init(AccessTokenRetriever accessTokenRetriever, AccessTokenValidator accessTokenValidator) {
        this.accessTokenRetriever = accessTokenRetriever;
        this.accessTokenValidator = accessTokenValidator;

        try {
            this.accessTokenRetriever.init();
        } catch (IOException e) {
            throw new KafkaException("The OAuth login configuration encountered an error when initializing the AccessTokenRetriever", e);
        }

        isInitialized = true;
    }

    protected AccessTokenRetriever createAccessTokenRetriever(Map<String, Object> jaasConfig) {

        final JaasOptionsUtils jou = new JaasOptionsUtils(jaasConfig);

        String clientId = jou.validateString(CLIENT_ID_CONFIG);
        String authority = jou.validateString(AUTHORITY_CONFIG);
        String certPath = jou.validateString(CERT_PATH_CONFIG);
        String privateKeyPath = jou.validateString(PRIVATE_KEY_PATH_CONFIG);
        String scope = jou.validateString(SCOPE_CONFIG);

        log.info("ClientId : {}, authority : {}, scope : {}", clientId, authority, scope);

        return new CertificateTokenRetriever(
                clientId,
                authority,
                certPath,
                privateKeyPath,
                scope);
    }

    @Override
    public void close() {
        if (accessTokenRetriever != null) {
            try {
                this.accessTokenRetriever.close();
            } catch (IOException e) {
                log.warn("The OAuth login configuration encountered an error when closing the AccessTokenRetriever", e);
            }
        }
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        checkInitialized();

        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback) {
                handleTokenCallback((OAuthBearerTokenCallback) callback);
            } else if (callback instanceof SaslExtensionsCallback) {
                handleExtensionsCallback((SaslExtensionsCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    private void handleTokenCallback(OAuthBearerTokenCallback callback) throws IOException {
        checkInitialized();
        String accessToken = accessTokenRetriever.retrieve();

        try {
            OAuthBearerToken token = accessTokenValidator.validate(accessToken);
            callback.token(token);
        } catch (ValidateException e) {
            log.warn(e.getMessage(), e);
            callback.error("invalid_token", e.getMessage(), null);
        }
    }

    private void handleExtensionsCallback(SaslExtensionsCallback callback) {
        checkInitialized();

        Map<String, String> extensions = new HashMap<>();

        for (Map.Entry<String, Object> configEntry : this.moduleOptions.entrySet()) {
            String key = configEntry.getKey();

            if (!key.startsWith(EXTENSION_PREFIX))
                continue;

            Object valueRaw = configEntry.getValue();
            String value;

            if (valueRaw instanceof String)
                value = (String) valueRaw;
            else
                value = String.valueOf(valueRaw);

            extensions.put(key.substring(EXTENSION_PREFIX.length()), value);
        }

        SaslExtensions saslExtensions = new SaslExtensions(extensions);

        try {
            OAuthBearerClientInitialResponse.validateExtensions(saslExtensions);
        } catch (SaslException e) {
            throw new ConfigException(e.getMessage());
        }

        callback.extensions(saslExtensions);
    }

    private void checkInitialized() {
        if (!isInitialized)
            throw new IllegalStateException(String.format("To use %s, first call the configure or init method", getClass().getSimpleName()));
    }

}
