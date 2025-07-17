package io.spoud.azure.auth.certificate;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.spoud.azure.auth.certificate.CertOAuthBearerLoginCallbackHandler.*;
import static org.apache.kafka.common.config.SaslConfigs.*;


class CertOAuthBearerLoginCallbackHandlerTest {

    @Test
    public void test() throws IOException, UnsupportedCallbackException {
        CertOAuthBearerLoginCallbackHandler certOAuthBearerLoginCallbackHandler = new CertOAuthBearerLoginCallbackHandler();

        Map<String, ?> config = Map.of(
                SASL_LOGIN_RETRY_BACKOFF_MS, 1000L,
                SASL_LOGIN_RETRY_BACKOFF_MAX_MS, 10000L,
                SASL_OAUTHBEARER_SCOPE_CLAIM_NAME, "scope",
                SASL_OAUTHBEARER_SUB_CLAIM_NAME, "sub"
        );
        String saslMechanism = "OAUTHBEARER";
        Map<String, Object> options = Map.of(
                SASL_OAUTHBEARER_EXPECTED_AUDIENCE, "39010f55-0b6c-4efd-a840-ed40ade4066a",
                CLIENT_ID_CONFIG, "3cf8283b-c4dd-47db-ac29-7cd4226102bb",
                AUTHORITY_CONFIG, "https://login.microsoftonline.com/b52245db-4800-4792-975a-1d9ed49512f2",
                SCOPE_CONFIG, "api://bd621c7c-d51d-4f86-a3fa-5d842c63dfce/.default",
                CERT_PATH_CONFIG, "certs/Example_Name/Example_Name.cer",
                PRIVATE_KEY_PATH_CONFIG, "certs/Example_Name/Example_Name.key"
        );

        List<AppConfigurationEntry> jassConfigEntries = List.of(new AppConfigurationEntry(
                "io.spoud.azure.auth.certificate.CertOAuthBearerLoginCallbackHandler",
                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                options));

        certOAuthBearerLoginCallbackHandler.configure(config, saslMechanism, jassConfigEntries);

        OAuthBearerTokenCallback oAuthBearerTokenCallback = new OAuthBearerTokenCallback();

        certOAuthBearerLoginCallbackHandler.handle(new Callback[]{oAuthBearerTokenCallback});

        OAuthBearerToken token = oAuthBearerTokenCallback.token();

        System.out.println(token);
    }
}