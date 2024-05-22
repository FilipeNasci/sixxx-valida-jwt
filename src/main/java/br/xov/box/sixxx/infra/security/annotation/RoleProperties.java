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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;


@ApplicationScoped
public class RoleProperties {

    private static final Logger LOGGER = Logger.getLogger(RoleProperties.class.getName());

    private final String requiredRolesString;     // String configurada de roles permitidos.

    @Inject
    public RoleProperties(
            @ConfigProperty(name = "security.allowed.roles") String requiredRolesString) {
        this.requiredRolesString = requiredRolesString;
    }

    public Set<String> getAllowedRoles() {
        try {
            LOGGER.log(Level.INFO, "The variable security.allowed.roles: {0}\"", requiredRolesString);
            return Arrays.stream(requiredRolesString.split(",")).map(String::trim).collect(Collectors.toSet());
        } catch (NullPointerException e) {
            LOGGER.log(Level.SEVERE, "The variable security.allowed.roles is null.\"", e);
            return new HashSet<>(); // Retorna um conjunto vazio em vez de null
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "An error occurred while processing security.allowed.roles.", e);
            return new HashSet<>(); // Retorna um conjunto vazio em caso de qualquer outra exceção
        }
    }
}









