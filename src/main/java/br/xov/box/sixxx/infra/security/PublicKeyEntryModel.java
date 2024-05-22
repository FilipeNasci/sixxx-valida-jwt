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

import java.security.PublicKey;

public class PublicKeyEntryModel {
    private final String kid;
    private final PublicKey publicKey;

    public PublicKeyEntryModel(String kid, PublicKey publicKey) {
        this.kid = kid;
        this.publicKey = publicKey;
    }

    public String getKid() {
        return kid;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
