package io.spoud.azure.auth.certificate;

import com.microsoft.aad.msal4j.*;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class TestTheLib {

    public static void main(String[] args) throws Exception {
        // Azure App Registration details
        String clientId = "3cf8283b-c4dd-47db-ac29-7cd4226102bb";
        String tenantId = "b52245db-4800-4792-975a-1d9ed49512f2";
        String authority = "https://login.microsoftonline.com/" + tenantId;

        //Use the script from the README.md to create the certificate and add it to your client
        String certPath = "certs/Example_Name/Example_Name.cer";
        String privateKeyPath = "certs/Example_Name/Example_Name.key"; // PEM format
        String scope = "api://bd621c7c-d51d-4f86-a3fa-5d842c63dfce/.default";

        // Load certificate
        X509Certificate certificate = loadCertificateFromResources(certPath);
        PrivateKey privateKey = loadPrivateKeyFromResources(privateKeyPath);

        // Build client credential
        IClientCredential credential = ClientCredentialFactory.createFromCertificate(privateKey, certificate);

        // Create the confidential client
        ConfidentialClientApplication app = ConfidentialClientApplication.builder(clientId, credential)
                .authority(authority)
                .build();

        // Define the scope (change this to what your app needs, e.g. a resource like Graph API)
        Set<String> scopes = Collections.singleton(scope);

        // Acquire token
        ClientCredentialParameters parameters = ClientCredentialParameters.builder(scopes).build();
        CompletableFuture<IAuthenticationResult> future = app.acquireToken(parameters);
        IAuthenticationResult result = future.get();

        // Output access token
        String token = result.accessToken();
        System.out.println("Access Token: " + token);

        String[] chunks = token.split("\\.");

        Base64.Decoder decoder = Base64.getUrlDecoder();

        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));

        System.out.println(header);
        System.out.println(payload);
    }

    private static X509Certificate loadCertificateFromResources(String resourcePath) throws Exception {
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath)) {
            if (in == null) throw new IllegalArgumentException("Certificate not found: " + resourcePath);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    private static PrivateKey loadPrivateKeyFromResources(String resourcePath) throws Exception {
        try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath)) {
            if (in == null) throw new IllegalArgumentException("Private key not found: " + resourcePath);
            String key = new String(in.readAllBytes());
            String privateKeyPem = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
    }
}
