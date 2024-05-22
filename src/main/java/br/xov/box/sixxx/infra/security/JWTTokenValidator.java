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

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.util.logging.Logger;

import static jakarta.ws.rs.core.HttpHeaders.AUTHORIZATION;

// Declara que esta classe é um provider JAX-RS que será automaticamente detectado e integrado pelo Quarkus.
@Provider
// Define a prioridade de execução dos filtros de requisição, neste caso, durante a fase de autenticação.
@Priority(Priorities.AUTHENTICATION)
public class JWTTokenValidator implements ContainerRequestFilter {

    // Injeta a classe de serviço que realizará a validação efetiva do token JWT.

    private final JWTTokenValidatorService jwtTokenValidatorService;

    @Inject
    public JWTTokenValidator(JWTTokenValidatorService jwtTokenValidatorService){
        this.jwtTokenValidatorService = jwtTokenValidatorService;
    }

    private static final String BEARER = "Bearer ";
    private static final Logger LOGGER = Logger.getLogger(JWTTokenValidator.class.getName());

    @Override
    public void filter(ContainerRequestContext requestContext) {

        // Captura o cabeçalho de autorização da requisição.
        String authorizationHeader = requestContext.getHeaderString(AUTHORIZATION);

        // Verifica se o cabeçalho está presente e se inicia com 'Bearer '.
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER)) {

            // Extrai o token do cabeçalho.
            String token = authorizationHeader.substring(BEARER.length());

            // Registra a tentativa de validação.
            LOGGER.info("Attempting to validate JWT token...");

            // Chama o serviço de validação do token.
            if (!jwtTokenValidatorService.validateToken(token)) {

                // Log e resposta em caso de falha na validação.
                LOGGER.warning("Token validation failed. Unauthorized access attempted.");
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());

            } else {

                // Log de sucesso na validação.
                LOGGER.info("Token successfully validated.");
            }
        } else {

            // Log e resposta caso o cabeçalho de autorização esteja ausente ou incorreto.
            LOGGER.warning("No Authorization header present or header does not start with 'Bearer'.");
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }
}
