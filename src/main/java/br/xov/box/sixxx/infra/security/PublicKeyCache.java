package br.xov.box.sixxx.infra.security;

/*
 * Este código é fornecido "como está", sem garantia de qualquer tipo, expressa ou
 * implícita, incluindo, mas não se limitando às garantias de comercialização,
 * adequação a um fim específico e não infração. Em nenhum caso os autores ou
 * detentores dos direitos autorais serão responsáveis por qualquer reclamação, danos
 * ou outra responsabilidade, seja em ação de contrato, delito ou de outra forma,
 * decorrente de, fora de ou em conexão com o software ou o uso ou outras
 * negociações no software.
 */

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.scheduler.Scheduled;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped  // Define que a classe é um bean gerenciado pelo CDI com um escopo de aplicação.
public class PublicKeyCache {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();
    private final Map<String, Instant> keyExpiry = new ConcurrentHashMap<>();
    private static final long EXPIRY_DURATION = 86400; // Duração de validade das chaves, definida em 24 horas.
    private static final Logger LOGGER = Logger.getLogger(PublicKeyCache.class.getName());


    private final String jwksUrl;

    @Inject
    public PublicKeyCache(
            @ConfigProperty(name = "security.jwks.url") String jwksUrl) {

        this.jwksUrl = jwksUrl;
    }

    // Tarefa agendada para atualizar as chaves públicas a cada 24 horas.
    @Scheduled(delay = 24, delayUnit = TimeUnit.HOURS, every = "24h")
    public void refreshKeys() {
        LOGGER.log(Level.INFO, "Executing refreshKeys on thread id: {0} with instance hash: {1}",
                new Object[]{Thread.currentThread().getId(), System.identityHashCode(this)});

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(jwksUrl)).GET().build();

        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                processSuccessfulResponse(response.body());
            } else {
                LOGGER.log(Level.SEVERE, "Failed to fetch keys from JWKS URL: {0}. HTTP status: {1}",
                        new Object[]{jwksUrl, response.statusCode()});
            }
        } catch (IOException | InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Error refreshing keys. Check connectivity with JWKS endpoint.", e);

            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void processSuccessfulResponse(String responseBody) {
        try {
            JsonNode jwks = objectMapper.readTree(responseBody);
            updateKeys(jwks);  // Atualiza as chaves com base na resposta JWKS.
            LOGGER.log(Level.INFO, "Keys successfully fetched and updated from JWKS URL: {0} at {1}",
                    new Object[]{jwksUrl, Instant.now()});
        } catch (JsonProcessingException e) {
            LOGGER.log(Level.SEVERE, "JSON parsing error while processing the response from JWKS URL: {0}", jwksUrl);
        }
    }




    // Atualiza o mapa de chaves públicas com as novas chaves obtidas.
    private void updateKeys(JsonNode jwks) {
        if (jwks.has("keys")) {
            for (JsonNode keyNode : jwks.get("keys")) {
                String kid = keyNode.get("kid").asText();
                PublicKey publicKey = decodePublicKey(keyNode);
                if (publicKey != null) {
                    publicKeys.put(kid, publicKey);
                    keyExpiry.put(kid, Instant.now().plusSeconds(EXPIRY_DURATION));
                    LOGGER.log(Level.INFO,"Key for KID:  {0} successfully fetched and updated.", kid);
                }
            }
        } else {
            LOGGER.log(Level.SEVERE,"No keys found in the provided JWKS from URL: {0}", jwksUrl);
        }
    }

    // Decodifica a chave pública RSA a partir do nó JSON.
    private PublicKey decodePublicKey(JsonNode keyNode) {
        try {
            String kty = keyNode.get("kty").asText();
            if ("RSA".equals(kty)) {
                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(keyNode.get("n").asText()));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(keyNode.get("e").asText()));
                RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to decode public key: {0}", e.getMessage());


        }
        return null;
    }

    // Retorna uma lista de chaves públicas válidas e kids respectivos, verificando se não estão expiradas.
    public List<PublicKeyEntryModel> getPublicKeyEntries() {
        List<PublicKeyEntryModel> validKeyEntries = new ArrayList<>();
        // Itera sobre todas as chaves no mapa de chaves públicas
        for (Map.Entry<String, PublicKey> entry : publicKeys.entrySet()) {
            String kid = entry.getKey();
            PublicKey key = entry.getValue();
            // Verifica se a chave não está expirada
            if (!isExpired(kid)) {
                // Se a chave for válida, adiciona ao par de chaves válidas
                validKeyEntries.add(new PublicKeyEntryModel(kid, key));
                LOGGER.log(Level.INFO, "Valid key found in cache for kid: {0}", kid);
            } else {
                // Se a chave estiver expirada, loga a informação
                LOGGER.log(Level.INFO, "Key expired for kid: {0}", kid);
            }
        }
        return validKeyEntries;  // Retorna a lista de entradas de chaves públicas válidas
    }

    // Verifica se a chave expirou baseado no tempo atual e no tempo de expiração armazenado.
    private boolean isExpired(String kid) {
        Instant expiry = keyExpiry.get(kid);
        return expiry == null || Instant.now().isAfter(expiry);
    }
}