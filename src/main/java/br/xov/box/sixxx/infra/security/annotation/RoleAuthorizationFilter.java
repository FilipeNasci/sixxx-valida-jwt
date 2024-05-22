package br.xov.box.sixxx.infra.security.annotation;

/*
 * Este código é fornecido "como está", sem garantia de qualquer tipo, expressa ou
 * implícita, incluindo, mas não se limitando às garantias de comercialização,
 * adequação a um fim específico e não infração. Em nenhum caso os autores ou
 * detentores dos direitos autorais serão responsáveis por qualquer reclamação, danos
 * ou outra responsabilidade, seja em ação de contrato, delito ou de outra forma,
 * decorrente de, fora de ou em conexão com o software ou o uso ou outras
 * negociações no software.
 */

import jakarta.inject.Inject;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;

@Provider
public class RoleAuthorizationFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = Logger.getLogger(RoleAuthorizationFilter.class);
    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";
    private static final int TOKEN_PREFIX_LENGTH = 7;

    @Context
    private ResourceInfo resourceInfo;

    private final RoleProperties roleProperties;

    @Inject
    public RoleAuthorizationFilter(
            @ConfigProperty(name = "security.allowed.roles") RoleProperties roleProperties) {

        this.roleProperties = roleProperties;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        RequireRole requireRole = resourceInfo.getResourceMethod().getAnnotation(RequireRole.class);
        if (requireRole != null) {
            LOGGER.info("Roles required for access: " + String.join(", ", requireRole.value()));

            // Verificar se as roles estão presentes nas roles permitidas do application.properties
            Set<String> allowedRoles = roleProperties.getAllowedRoles();
            for (String role : requireRole.value()) {
                if (!allowedRoles.contains(role)) {
                    LOGGER.warn("Unauthorized role specified: " + role);
                    requestContext.abortWith(jakarta.ws.rs.core.Response.status(jakarta.ws.rs.core.Response.Status.FORBIDDEN).build());
                    return;
                }
            }

            Set<String> userRoles = getUserRolesFromToken(requestContext);

            // Verificar se pelo menos uma das roles do usuário está presente nas roles necessárias
            boolean authorized = false;
            for (String role : requireRole.value()) {
                if (userRoles.contains(role)) {
                    authorized = true;
                    break;
                }
            }

            if (!authorized) {
                LOGGER.error("Authorization failed. User roles do not include the required roles.");
                requestContext.abortWith(jakarta.ws.rs.core.Response.status(jakarta.ws.rs.core.Response.Status.FORBIDDEN).build());
            } else {
                LOGGER.info("Authorization successful. Proceeding with request.");
            }
        }
    }

    private Set<String> getUserRolesFromToken(ContainerRequestContext requestContext) {
        String authorizationHeader = requestContext.getHeaderString(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER)) {
            String token = authorizationHeader.substring(TOKEN_PREFIX_LENGTH);
            return decodeJWTAndGetRoles(token);
        }
        LOGGER.warn("Authorization header is missing or invalid");
        return new HashSet<>(); // Retorna um conjunto vazio se o cabeçalho de autorização for inválido ou não estiver presente
    }

    private Set<String> decodeJWTAndGetRoles(String token) {
        LOGGER.info("Decoding JWT: " + token);  // Log do token recebido
        try {
            DecodedJWT jwt = JWT.decode(token);
            if (jwt != null) {
                LOGGER.info("JWT decoded successfully");
                // Acessa a claim "realm_access" e então a lista "roles" dentro dela
                Map<String, Claim> claims = jwt.getClaims();
                Claim realmAccess = claims.get("realm_access");
                if (realmAccess != null) {
                    List<String> roles = (List<String>) realmAccess.asMap().get("roles");
                    if (roles != null && !roles.isEmpty()) {
                        LOGGER.info("Roles extracted from JWT: " + roles);
                        return new HashSet<>(roles);
                    } else {
                        LOGGER.warn("No roles found in JWT under 'realm_access'.");
                    }
                } else {
                    LOGGER.warn("'realm_access' claim is missing in JWT.");
                }
            } else {
                LOGGER.warn("JWT decoding returned null.");
            }
        } catch (JWTDecodeException e) {
            LOGGER.error("Error decoding JWT: " + e.getMessage(), e);
        }
        return new HashSet<>(); // Retorna um conjunto vazio em caso de erro ou falta de papéis
    }

}

