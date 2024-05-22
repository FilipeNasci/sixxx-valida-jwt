package br.xov.box.sixxx.infra;

/*
 * Este código é fornecido "como está", sem garantia de qualquer tipo, expressa ou
 * implícita, incluindo, mas não se limitando às garantias de comercialização,
 * adequação a um fim específico e não infração. Em nenhum caso os autores ou
 * detentores dos direitos autorais serão responsáveis por qualquer reclamação, danos
 * ou outra responsabilidade, seja em ação de contrato, delito ou de outra forma,
 * decorrente de, fora de ou em conexão com o software ou o uso ou outras
 * negociações no software.
 */

import br.xov.box.sixxx.infra.security.PublicKeyCache;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.logging.Logger;

@Singleton
public class ApplicationManager {

    private static final Logger LOGGER = Logger.getLogger(ApplicationManager.class.getName());
    private final PublicKeyCache publicKeyCache;

    @Inject
    public ApplicationManager(PublicKeyCache publicKeyCache){
        this.publicKeyCache = publicKeyCache;
    }

    void onStart(@Observes StartupEvent ev){
        this.publicKeyCache.refreshKeys();
        LOGGER.info("Application has started successfully.");
    }



}
