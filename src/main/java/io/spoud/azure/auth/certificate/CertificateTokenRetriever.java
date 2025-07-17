package io.spoud.azure.auth.certificate;

import com.microsoft.aad.msal4j.*;
import org.apache.kafka.common.security.oauthbearer.internals.secured.AccessTokenRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class CertificateTokenRetriever implements AccessTokenRetriever {

    private static final Logger log = LoggerFactory.getLogger(CertificateTokenRetriever.class);
    private final String clientId, authority, certPath, privateKeyPath;
    private final Set<String> scopes;

    private CertificateFactory certificateFactory;
    private KeyFactory keyFactory;

    private ConfidentialClientApplication confidentialClientApplication;
    private ClientCredentialParameters clientCredentialParameters;


    public CertificateTokenRetriever(String clientId, String authority, String certPath, String privateKeyPath, String scope) {
        this.clientId = clientId;
        this.authority = authority;
        this.certPath = certPath;
        this.privateKeyPath = privateKeyPath;
        this.scopes = Collections.singleton(scope);
    }

    @Override
    public String retrieve() throws IOException {
        CompletableFuture<IAuthenticationResult> future = confidentialClientApplication.acquireToken(clientCredentialParameters);
        IAuthenticationResult result;
        try {
            result = future.get();
            log.debug("Certificate authentication result: scopes {}, accessToken {}, expires {}", result.scopes(), result.accessToken(), result.expiresOnDate());
        } catch (InterruptedException | ExecutionException e) {
            throw new IOException(e);
        }

        return result.accessToken();
    }

    @Override
    public void init() throws IOException {
        AccessTokenRetriever.super.init();

        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
            keyFactory = KeyFactory.getInstance("RSA");

            // Load certificate
            X509Certificate certificate = loadCertificateFromPath(certPath);
            PrivateKey privateKey = loadPrivateKeyFromPath(privateKeyPath);

            // Build client credential
            IClientCredential credential = ClientCredentialFactory.createFromCertificate(privateKey, certificate);

            // Create the confidential client
            confidentialClientApplication = ConfidentialClientApplication.builder(clientId, credential)
                    .authority(authority)
                    .build();

            // Setup the parameters
            clientCredentialParameters = ClientCredentialParameters.builder(scopes).build();

        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Could not initialize", e);
            throw new RuntimeException(e);
        }
    }

    private X509Certificate loadCertificateFromPath(String certificatePath) throws CertificateException, IOException {
        log.debug("loadCertificateFromPath: {}", certificatePath);
        Path path = Paths.get(certificatePath);
        try (InputStream inputStream = Files.newInputStream(path)) {
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
    }

    private PrivateKey loadPrivateKeyFromPath(String privateKeyPath) throws IOException, InvalidKeySpecException {
        log.debug("loadPrivateKeyFromPath: {}", privateKeyPath);
        Path path = Paths.get(privateKeyPath);
        try (InputStream inputStream = Files.newInputStream(path)) {
            String key = new String(inputStream.readAllBytes());
            String privateKeyPem = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);

            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        }
    }
}
