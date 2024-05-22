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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@ApplicationScoped
public class JWTTokenValidatorService {

    private final PublicKeyCache publicKeyCache;  // Cache de chaves públicas para recuperar a chave necessária para verificar o token.
    private final String requiredScopesString;    // String configurada de escopos permitidos.
    private final String requiredRolesString;     // String configurada de roles permitidos.
    private final String requiredJwtIssuer;       // Emissor de JWT esperado, configurado no sistema.

    @Inject
    public JWTTokenValidatorService(
            PublicKeyCache publicKeyCache,
            @ConfigProperty(name = "security.allowed.scopes") String requiredScopesString,
            @ConfigProperty(name = "security.allowed.roles") String requiredRolesString,
            @ConfigProperty(name = "security.jwt.issuer") String requiredJwtIssuer) {

        this.publicKeyCache = publicKeyCache;
        this.requiredScopesString = requiredScopesString;
        this.requiredRolesString = requiredRolesString;
        this.requiredJwtIssuer = requiredJwtIssuer;
    }



    private static final Logger LOGGER = Logger.getLogger(JWTTokenValidatorService.class.getName());  // Logger para registrar informações e erros.

    public boolean validateToken(String token) {
        try {
            // Decodifica o token sem verificar sua assinatura para extrair o 'kid' e outras informações.
            DecodedJWT jwt = JWT.decode(token);
            String kid = jwt.getKeyId();
            List<PublicKeyEntryModel> entries = publicKeyCache.getPublicKeyEntries();
            PublicKeyEntryModel selectedEntry = null;

            // Itera sobre as entradas de chave para encontrar a correspondente ao 'kid' especificado.
            for (PublicKeyEntryModel entry : entries) {
                // Procura uma chave que corresponda ao 'kid' especificado no token.
                if (entry.getKid().equals(kid) && entry.getPublicKey() instanceof RSAPublicKey) {
                    selectedEntry = entry;
                    break;
                }
            }

            // Se uma chave correspondente for encontrada, configura o algoritmo e verifica o token.
            if (selectedEntry != null) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) selectedEntry.getPublicKey();
                Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, null);
                JWTVerifier verifier = JWT.require(algorithm).withIssuer(requiredJwtIssuer).build();
                // Verifica se o token é válido com a chave e o emissor corretos.
                verifier.verify(token);
                LOGGER.log(Level.INFO,"JWT verified successfully for kid: {0}", kid);
                return true;
            } else {
                LOGGER.log(Level.WARNING, "No appropriate RSAPublicKey found for KID: {0}", kid);
            }

            // Após a verificação inicial, confirma se o token possui as claims, escopos e roles necessários.
            if (!validateClaims(jwt) || !validateRoles(jwt) || !validateScope(jwt)) {
                return false;
            }

        } catch (JWTVerificationException e) {
            LOGGER.log(Level.SEVERE, "JWT verification failed: {0}", e.getMessage());
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Internal Server Error: {0} ", e.getMessage());
        }
        return false;
    }

    // Valida o emissor, a validade e o momento de início de validade do token.
    private boolean validateClaims(DecodedJWT jwt) {

        // Validate issuer
        if (!requiredJwtIssuer.equals(jwt.getIssuer())) {
            LOGGER.log(Level.SEVERE, "Invalid issuer: {0}", jwt.getIssuer());
            return false;
        }
        // Check for token expiration
        if (jwt.getExpiresAt() != null && jwt.getExpiresAt().getTime() / 1000 < (System.currentTimeMillis() / 1000 + 300)) {
            LOGGER.log(Level.WARNING, "Token is about to expire in less than 5 minutes.");
            return false;
        }
        // Check not before
        if (jwt.getNotBefore() != null && jwt.getNotBefore().getTime() / 1000 > System.currentTimeMillis() / 1000) {
            LOGGER.log(Level.SEVERE, "Token is not yet valid.");
            return false;
        }
        return true;
    }

    // Valida se o token possui o scope necessário.
    private boolean validateScope(DecodedJWT jwt) {
        Set<String> requiredScopes = Arrays.stream(requiredScopesString.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        String scopeClaim = jwt.getClaim("scope").asString();
        List<String> tokenScopes = Arrays.asList(scopeClaim.split(" "));
        if (!tokenScopes.containsAll(requiredScopes)) {
            LOGGER.log(Level.SEVERE, "Required scopes are missing in the token.");
            return false;
        }
        return true;
    }

    // Valida se o token possui uma roles necessária.
    private boolean validateRoles(DecodedJWT jwt) {
        Set<String> requiredRoles = Arrays.stream(requiredRolesString.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        Map<String, Object> realmAccess = jwt.getClaim("realm_access").asMap();
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            List<String> roles = (List<String>) realmAccess.get("roles");
            for (String requiredRole : requiredRoles) {
                if (roles.contains(requiredRole)) {
                    return true;
                }
            }
        }
        LOGGER.log(Level.WARNING, "The JWT does not contain any roles or does not match the required roles.");
        return false;
    }
}