package br.xov.box.sixxx.resource;

/*
 * Este código é fornecido "como está", sem garantia de qualquer tipo, expressa ou
 * implícita, incluindo, mas não se limitando às garantias de comercialização,
 * adequação a um fim específico e não infração. Em nenhum caso os autores ou
 * detentores dos direitos autorais serão responsáveis por qualquer reclamação, danos
 * ou outra responsabilidade, seja em ação de contrato, delito ou de outra forma,
 * decorrente de, fora de ou em conexão com o software ou o uso ou outras
 * negociações no software.
 */

import br.xov.box.sixxx.infra.security.annotation.RequireRole;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.jboss.logging.Logger;

@Path("/hello")
public class HelloResource {

    private static final Logger LOGGER = Logger.getLogger(HelloResource.class);

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @RequireRole({"uma_authorization"})
    public String hello(@HeaderParam("Authorization") String authorizationHeader) {
        LOGGER.info("Received Authorization Header: " + authorizationHeader);
        LOGGER.info("Hello.");
        return "Received Authorization Header: " + authorizationHeader;
    }
}