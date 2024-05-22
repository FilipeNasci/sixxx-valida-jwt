# sixxx-valida-jwt-offline

# Sistema de Segurança Baseado em JWT

## Visão Geral

Este sistema é desenvolvido tanto para ser um modelo prático quanto uma solução robusta, atendendo especificamente às necessidades de segurança e desempenho em aplicações que utilizam JSON Web Tokens (JWT) para autenticação offline e autorização. Organizado em dois pacotes principais, ele facilita o gerenciamento de chaves públicas e o controle de acesso baseado em roles. Destinado a aplicações modernas, o sistema exemplifica boas práticas de desenvolvimento de software e assegura escalabilidade, eficiência e alta confiabilidade, garantindo a segurança nas operações de autenticação e autorização em ambientes com rigorosas exigências de segurança.

### Propriedades Principais

- **Java Version**: 17, 11
- **Compiler Plugin Version**: 3.11.0
- **Source Encoding**: UTF-8
- **Quarkus Version**: 3.2.12.Final

### Dependências

- **quarkus-arc**: Suporte à injeção de dependências.
- **quarkus-resteasy-reactive-jackson**: Para APIs RESTful reativas com serialização/deserialização JSON.
- **java-jwt (Auth0)**: Versão 4.4.0 para criação e validação de JWTs.
- **quarkus-scheduler**: Para agendamento de tarefas recorrentes.
- **quarkus-junit5**: Integração com JUnit 5 para testes.
- **rest-assured**: Testes de API REST.
- **jakarta.validation-api**: Versão 3.0.2 para validação de dados de entrada nas APIs.

### Configurações do `application.properties`


- **quarkus.scheduler.enabled**: Ativa o sistema de agendamento do Quarkus, permitindo a execução de tarefas agendadas. Não alterar.
- **quarkus.log.category."br.org.caixa".level**: Define o nível de log para INFO para qualquer classe dentro do pacote.
- **security.jwks.url**: URL do servidor de autenticação para capturar chaves públicas necessárias para verificar os tokens JWT usados no seu sistema de segurança.
- **security.jwt.issuer**: URL do emissor do JWT, usada para validar a autenticidade dos tokens recebidos.
- **security.allowed.roles**: Lista os roles que têm permissão para acessar determinadas funcionalidades da aplicação.
- **security.allowed.scopes**: Define os escopos aceitáveis nos tokens JWT para autorização de acesso a recursos específicos.

## Componentes

### Pacote `br.gov.caixa.sixxx.infra`

Este pacote contém a classe que gerencia eventos chave do ciclo de vida:

- **ApplicationManager**

### Pacote `br.gov.caixa.sixxx.infra.security`

Este pacote contém classes cruciais para o gerenciamento de chaves públicas e validação de tokens:

- **PublicKeyCache**
- **JWTTokenValidator**
- **JWTTokenValidatorService**
- **PublicKeyEntry**

### Pacote `br.gov.caixa.sixxx.infra.security.annotation`

Este pacote inclui anotações e filtros para aplicar restrições de acesso nos métodos de serviços:

- **RequireRole**
- **RoleAuthorizationFilter**


---


## Classe: ApplicationManager

Localizada dentro do contexto de segurança, a classe `ApplicationManager` é responsável por gerenciar eventos de ciclo de vida da aplicação, particularmente ao iniciar a aplicação. Ela é marcada como `@Singleton`, indicando que existe apenas uma instância desta classe durante o ciclo de vida da aplicação.

### Funcionalidades

- **Inicialização de Componentes**: Gerencia a inicialização de componentes essenciais da aplicação, como a atualização das chaves públicas usadas para validar tokens JWT.

### Atributos

- **LOGGER**: Utilizado para registrar informações e atividades da aplicação, ajudando no diagnóstico e na auditoria operacional.

### Injeção de Dependências

- **publicKeyCache**: Dependência injetada que representa o cache de chaves públicas. É utilizado para atualizar as chaves públicas no início da aplicação.

### Eventos do Ciclo de Vida

#### Método: onStart

- **Descrição**: Método invocado automaticamente ao iniciar a aplicação. Ele é responsável por atualizar as chaves públicas e registrar o sucesso da inicialização.
- **Evento Observado**:
  - `StartupEvent ev`: Evento disparado pelo Quarkus ao iniciar a aplicação, usado aqui para acionar a atualização das chaves.
- **Exceções**:
  - `IOException`: Lançada se ocorrer um erro ao acessar dados externos durante a atualização das chaves.
  - `InterruptedException`: Lançada se o processo de atualização das chaves for interrompido inesperadamente.

### Utilização

A classe `ApplicationManager` é essencial para assegurar que componentes críticos da aplicação sejam inicializados corretamente. Por exemplo, garantindo que o cache de chaves públicas esteja atualizado antes de qualquer operação de validação de token ser permitida.

### Importância

A `ApplicationManager` assegura que todos os preparativos necessários são feitos antes de a aplicação começar a responder a requisições, contribuindo para a estabilidade e segurança operacional. Além disso, através dos logs gerados, oferece visibilidade sobre o estado de inicialização da aplicação.

---

## Classe: PublicKeyCache

Localizada no pacote `br.gov.caixa.sixxx.infra.security`, a classe `PublicKeyCache` é responsável por gerenciar um cache de chaves públicas usadas para validar tokens JWT em aplicações que exigem autenticação e segurança aprimoradas.

### Funcionalidades

- **Gerenciamento de Chaves Públicas**: Mantém um repositório de chaves públicas que são atualizadas periodicamente de um endpoint JWKS (JSON Web Key Set).
- **Atualização Automática**: Implementa uma tarefa agendada para atualizar as chaves a cada 24 horas, garantindo que as chaves sejam sempre recentes e válidas.

### Métodos Principais

#### Método: refreshKeys
- **Descrição**: Executado automaticamente com base em uma programação definida, este método atualiza o cache de chaves públicas consultando o endpoint JWKS configurado.
- **Processo**:
  - **Consulta HTTP**: Realiza uma chamada HTTP ao endpoint JWKS.
  - **Processamento de Resposta**: Decodifica a resposta e atualiza o cache de chaves com quaisquer novas chaves ou atualizações.
  - **Tratamento de Erros**: Captura e registra erros que podem ocorrer durante a consulta ou o processamento da resposta.

### Atualização de Chaves

- **Extração de Chaves**: Decodifica as chaves do formato JWKS e as converte para objetos `PublicKey` utilizáveis.
- **Armazenamento no Cache**: Armazena chaves atualizadas no cache, juntamente com suas informações de expiração, garantindo que apenas chaves válidas sejam usadas para validação de tokens.

### Decodificação de Chaves Públicas

- **Método**: decodePublicKey
- **Descrição**: Decodifica uma chave pública RSA a partir dos dados contidos em um nó JSON representando uma chave JWKS.
- **Inputs**:
  - `JsonNode keyNode`: O nó JSON contendo os dados da chave pública.
- **Outputs**:
  - `PublicKey`: Retorna um objeto `PublicKey` se a decodificação for bem-sucedida; caso contrário, retorna `null`.

### Validação de Expiração de Chaves

- **Método**: isExpired
- **Descrição**: Verifica se uma chave específica no cache expirou com base no tempo atual e no tempo de expiração armazenado.
- **Parâmetros**:
  - `String kid`: O identificador da chave (KID) cuja expiração será verificada.
- **Retorno**: Retorna `true` se a chave expirou; caso contrário, retorna `false`.

### Configuração

- **Configuração Externa**: Utiliza propriedades configuradas externamente, como a URL do endpoint JWKS, para buscar atualizações de chaves.
- **Logs e Diagnóstico**:
  - **Logs Informativos**: Registra cada atualização de chave bem-sucedida, fornecendo transparência sobre as operações realizadas.
  - **Logs de Erro**: Fornece detalhes sobre falhas no processo de atualização de chaves, facilitando a resposta rápida a incidentes relacionados à segurança.

### Importância Estratégica

- **Segurança Reforçada**: Ao manter um cache atualizado de chaves públicas, a classe contribui significativamente para a segurança das operações de validação de tokens JWT, essencial para prevenir acessos não autorizados e potenciais brechas de segurança em aplicações críticas.


---

## Classe: PublicKeyEntry

A classe `PublicKeyEntry` está localizada dentro do pacote de segurança e é utilizada para modelar a associação entre um identificador de chave (KID) e uma chave pública. Esta classe é fundamental para o gerenciamento de chaves públicas em sistemas que utilizam JWT (JSON Web Tokens) para autenticação e autorização.

### Descrição

`PublicKeyEntry` é uma classe simples que encapsula um par de KID e chave pública, facilitando o gerenciamento e a recuperação de chaves públicas no cache de chaves.

### Atributos

- **kid**: Identificador da chave (Key ID). É uma string que serve como identificador único para a chave pública associada.
- **publicKey**: Objeto de chave pública do tipo `PublicKey`. Contém a chave pública propriamente dita que pode ser usada para verificar assinaturas de tokens JWT.

### Construtor

- **PublicKeyEntry(String kid, PublicKey publicKey)**:
  - **Descrição**: Constrói uma nova instância da classe `PublicKeyEntry` com um identificador de chave e a chave pública correspondente.
  - **Parâmetros**:
    - `String kid`: O identificador da chave.
    - `PublicKey publicKey`: A chave pública associada ao identificador.

### Métodos

#### Método: getKid

- **Descrição**: Retorna o identificador da chave (KID) associado a esta entrada.
- **Retorno**: `String` - O KID da chave.

#### Método: getPublicKey

- **Descrição**: Retorna a chave pública associada a este KID.
- **Retorno**: `PublicKey` - O objeto de chave pública.

### Utilização

A classe `PublicKeyEntry` é usada principalmente em sistemas que precisam de um método organizado para armazenar e recuperar chaves públicas por seus identificadores. Isso é particularmente útil em caches de chaves públicas onde cada chave deve ser rapidamente acessível para a validação de assinaturas de tokens JWT durante o processo de autenticação.



---

## Classe: TokenValidation

Localizada no pacote `br.gov.caixa.sixxx.infra.security`, a classe `TokenValidation` é responsável pela autenticação de requisições HTTP através da validação de tokens JWT. Esta classe implementa a interface `ContainerRequestFilter`, proporcionando um mecanismo integrado ao ciclo de requisições JAX-RS para interceptar e validar tokens de segurança.

### Funcionalidades

- **Interceptação de Requisições**: Como um filtro de requisição, `TokenValidation` intercepta requisições HTTP para verificar a presença e a validade de tokens JWT no cabeçalho de autorização.
- **Validação de JWT**: Utiliza métodos para decodificar e validar tokens JWT, garantindo que eles sejam não apenas tecnicamente corretos, mas também autorizados para acessar recursos específicos.

### Método: filter

- **Descrição**: Executa a verificação e validação do token JWT contido no cabeçalho de autorização das requisições HTTP. Este método é invocado automaticamente pelo servidor de aplicação sempre que uma requisição é feita.
- **Parâmetros**:
  - `ContainerRequestContext requestContext`: Contexto da requisição atual, utilizado para extrair e manipular informações como cabeçalhos HTTP.
- **Comportamento**: O método não retorna um valor diretamente, mas pode terminar a requisição prematuramente, retornando uma resposta HTTP de erro se o token não passar nas verificações de validade.

### Processo de Validação

1. **Extrair Token**: O token é extraído do cabeçalho de autorização, que deve começar com 'Bearer '.
2. **Chamada ao Serviço de Validação**: O token extraído é passado para o serviço `JWTTokenValidatorService` através do método `validateToken`. Este serviço realiza uma série de verificações para assegurar a validade do token. Se o token for considerado inválido, a requisição é interrompida com uma resposta `401 Unauthorized`.
3. **Decodificar e Verificar**: O token é decodificado para verificar sua assinatura e validar campos essenciais como expiração, emissor e escopo.
4. **Validação de Escopo e Permissões**: Além da validação técnica, a classe verifica se o token possui as permissões necessárias para a operação solicitada.

### Tratamento de Erros

- **Falha na Validação**: Se a validação do token falhar, a requisição é interrompida com uma resposta `401 Unauthorized`.
- **Erro no Processo de Validação**: Problemas como erro na decodificação do token ou falhas na comunicação com o serviço de chave pública resultam em uma resposta `500 Internal Server Error`.

### Logs

- A classe registra atividades significativas e erros, facilitando o rastreamento e a depuração de problemas relacionados à autenticação.

### Configuração

- A classe depende de configurações externas para obter URLs de serviços de chave pública e definições de políticas de segurança, que são injetadas via `@ConfigProperty`.

--- 


## Classe: JWTTokenValidatorService

Localizada no pacote `br.gov.caixa.sixxx.infra.security`, a classe `JWTTokenValidatorService` é essencial para a segurança de aplicações que utilizam autenticação baseada em JWT (JSON Web Token). Ela é responsável por validar tokens JWT, assegurando que sejam autênticos e autorizados para operações específicas dentro da aplicação.

### Funcionalidades

- **Verificação de Chave Pública**: Utiliza o `PublicKeyCache` para recuperar a chave pública correspondente ao identificador de chave (KID) fornecido pelo token, essencial para a verificação da assinatura do token.
- **Validação de Claims de JWT**: Assegura que o token contém todas as claims necessárias e que estas estão corretas, como emissor, validade e escopo.

### Método: validateToken

- **Descrição**: Este método realiza a validação do token JWT, incluindo a verificação da assinatura, a validade das claims e as permissões necessárias representadas por escopos e roles.
- **Parâmetros**:
  - `String token`: o token JWT em formato de string que será validado.
- **Retorno**: Retorna `true` se o token for válido em todos os aspectos verificados, caso contrário, retorna `false`.
- **Processo de Validação**:
  - **Extração do KID**: Decodifica o token para extrair o KID sem verificar a assinatura.
  - **Recuperação da Chave Pública**: Obtém a chave pública do cache correspondente ao KID.
  - **Configuração do Verificador de JWT**: Configura um `JWTVerifier` com a chave pública e o emissor esperado para validar o token.
  - **Verificação de Claims Adicionais**: Verifica outras claims importantes como a expiração e a validade inicial do token.
  - **Validação de Escopos e Roles**: Confirma que o token possui os escopos e roles necessários para a operação desejada.

### Tratamento de Erros

- **Erro na Verificação**: Registra e trata erros que podem surgir durante a verificação do token, como problemas na decodificação, chaves públicas faltantes ou claims inválidas.
- **Logs de Atividades**: Fornece logs detalhados para diagnóstico e auditoria de segurança, ajudando na identificação rápida de problemas relacionados à autenticação.

### Configuração

- As configurações necessárias para a operação da classe, como URLs de serviços de chaves públicas e definições de políticas de segurança, são injetadas através de `@ConfigProperty`. Isso permite uma flexibilidade e adaptabilidade para diferentes ambientes de execução.

### Utilização

- A classe pode ser utilizada por serviços de autenticação ou por filtros de requisições para garantir que apenas usuários autenticados e autorizados acessem recursos críticos da aplicação.

### Logs e Diagnóstico

- **Logs Informativos**: Registra cada etapa do processo de validação, oferecendo transparência sobre as operações realizadas.
- **Logs de Erro**: Fornece detalhes sobre falhas na validação, facilitando a correção de configurações ou a resposta a incidentes de segurança.

### Importância Estratégica

- **Segurança Reforçada**: Ao validar rigorosamente cada token, a classe contribui significativamente para a segurança geral da aplicação, prevenindo acessos não autorizados e potenciais brechas de segurança.

---

## Anotação: RequireRole

Localizada no pacote `br.gov.caixa.sixxx.infra.security.annotation`, a anotação `RequireRole` é uma ferramenta de segurança que especifica restrições de acesso baseadas em papéis para métodos em aplicações Java. Ela é utilizada para declarar de forma explícita quais papéis são necessários para a execução de um determinado método, integrando controle de acesso diretamente na camada de serviço da aplicação.

## Detalhes da Anotação

- **@Retention(RetentionPolicy.RUNTIME)**: Esta especificação indica que a anotação é retida em tempo de execução, permitindo que seja lida e interpretada durante a execução do programa.

- **@Target(ElementType.METHOD)**: Define que esta anotação pode ser aplicada somente a métodos. Não é aplicável a classes, pacotes ou outros elementos.

- **value**: Um array de `String` que lista os papéis necessários para acessar o método anotado. Cada string no array representa um papel específico que um usuário deve possuir para invocar o método.

## Uso

Para utilizar a anotação `RequireRole`, ela deve ser colocada diretamente acima do método ao qual se deseja restringir o acesso, especificando os papéis apropriados como valores da anotação. Aqui está um exemplo simplificado de como aplicar `RequireRole`:

```java
package br.gov.caixa.sixxx.resource;

import annotation.security.infra.br.xov.box.sixxx.RequireRole;

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
    @RequireRole(value = {"MAGISTRADO", "SERVIDOR"})
    public String hello(@HeaderParam("Authorization") String authorizationHeader) {
        LOGGER.info("Received Authorization Header: " + authorizationHeader);
        LOGGER.info("Hello.");
        return "Received Authorization Header: " + authorizationHeader;
    }
} 
```

---

## Classe: RoleAuthorizationFilter

- Localizada no pacote `br.gov.caixa.sixxx.infra.security.annotation`, a classe `RoleAuthorizationFilter` implementa a interface `ContainerRequestFilter` do JAX-RS para prover controle de acesso baseado em papéis para APIs REST. Ela usa a anotação `RequireRole` para determinar se um usuário tem os papéis necessários para acessar um método específico.
- `RoleAuthorizationFilter` é uma parte essencial da camada de segurança, garantindo que apenas usuários autorizados com os papéis corretos possam acessar funcionalidades restritas da API. Implementado de forma eficaz, esse filtro ajuda a manter o controle rigoroso sobre quem pode realizar ações sensíveis dentro de uma aplicação, alinhando-se com práticas recomendadas de segurança e governança de identidade.

## Métodos Principais

### Método: filter
- **Descrição**: Executa a validação de papéis baseada na anotação `RequireRole` aplicada a métodos de recursos. Se os papéis exigidos pela anotação não estiverem presentes no token JWT do usuário, a requisição é abortada com uma resposta de status `FORBIDDEN`.
- **Inputs**: 
  - `ContainerRequestContext requestContext` - Contexto da requisição que contém informações como cabeçalhos HTTP.
- **Outputs**: Não retorna valores diretamente, mas pode abortar a execução da requisição, interrompendo o processamento com uma resposta HTTP adequada.
- **Exceções**: Não lança exceções explicitamente; manipula erros internamente e responde com status HTTP apropriado.

### Método: getUserRolesFromToken
- **Descrição**: Extrai e retorna os papéis do usuário a partir do token JWT presente no cabeçalho de autorização da requisição.
- **Inputs**: 
  - `ContainerRequestContext requestContext` - Contexto da requisição atual.
- **Outputs**: Retorna um conjunto de strings que representa os papéis do usuário.

### Método: decodeJWTAndGetRoles
- **Descrição**: Decodifica o token JWT e extrai os papéis do usuário a partir da claim `realm_access`.
- **Inputs**: 
  - `String token` - O token JWT como string.
- **Outputs**: Retorna um conjunto de strings contendo os papéis do usuário.

## Funcionalidades

- **Verificação de Papéis Permitidos**: Antes de validar os papéis do usuário, verifica se os papéis requeridos pela anotação `RequireRole` estão dentro dos papéis permitidos configurados no sistema. Isso previne a autorização baseada em configurações desatualizadas ou incorretas.

- **Extração e Validação de Papéis**: Utiliza o token JWT para verificar se o usuário possui pelo menos um dos papéis necessários para acessar o método anotado. Se não, a requisição é interrompida.

- **Logs Detalhados**: Registra informações detalhadas sobre o processo de decodificação e validação para facilitar o diagnóstico e a manutenção.


## Classe: RoleProperties

- Localizada na aplicação, a classe `RoleProperties` gerencia a configuração de papéis permitidos dentro da aplicação, especificamente para o controle de acesso baseado em papéis. Ela é designada como `@ApplicationScoped`, garantindo uma única instância durante o ciclo de vida da aplicação, o que a torna ideal para acessar configurações centralizadas.
- `RoleProperties` desempenha um papel crucial em garantir que os controles de acesso baseados em papéis sejam gerenciados de forma eficaz, proporcionando um ponto único de configuração e verificação de papéis autorizados. Esta abordagem não só simplifica a manutenção da segurança, mas também assegura que as mudanças nos requisitos de acesso sejam refletidas rapidamente em toda a aplicação.

## Métodos Principais

### Método: getAllowedRoles
- **Descrição**: Recupera um conjunto de papéis permitidos a partir de uma propriedade de configuração definida.
- **Inputs**: Não possui entradas explícitas.
- **Outputs**: Retorna um `Set<String>` que contém os papéis permitidos conforme configurados. Pode retornar `null` se houver um erro ao processar a configuração ou se a configuração estiver ausente.
- **Exceções**: Pode logar e propagar exceções relacionadas à ausência da configuração ou erros durante o processamento da string de configuração.

## Funcionalidades

- **Configuração de Papéis**: Utiliza a anotação `@ConfigProperty` para injetar a string de configuração `security.allowed.roles` diretamente da configuração do ambiente. Isso permite uma gestão flexível e centralizada dos papéis permitidos dentro da aplicação.

- **Processamento de Papéis**: Converte a string de papéis permitidos em um conjunto, facilitando a verificação de acesso e integração com outras partes do sistema de segurança.

- **Logs de Diagnóstico**: Gera logs informativos e de erro para ajudar na identificação de problemas e no monitoramento da configuração de segurança.

---

## Classe: HelloResource

A classe `HelloResource` é um componente de serviço web RESTful localizado no pacote de segurança e é responsável por fornecer um ponto de acesso HTTP para operações de teste e demonstração dentro de uma aplicação. A classe usa anotações JAX-RS para definir rotas e métodos HTTP.

### Atributos

- **LOGGER**: Utilizado para registrar informações sobre as operações realizadas, facilitando o diagnóstico e a auditoria de atividades.

### Anotações de Caminho e Método

- **@Path("/hello")**: Define o caminho da URI para o recurso REST. Qualquer requisição HTTP enviada para `/hello` será tratada por esta classe.
- **@GET**: Indica que o método `hello` é responsivo a requisições HTTP GET.
- **@Produces(MediaType.TEXT_PLAIN)**: Especifica que a resposta do método será em texto plano.

### Segurança e Controle de Acesso

- **@RequireRole({"uma_authorization"})**: Anotação customizada que especifica que o acesso ao método `hello` requer que o solicitante possua a role `uma_authorization`. Isso é usado para controlar o acesso baseado em roles dentro da aplicação.

### Método: hello

- **Descrição**: Método que é chamado em resposta a uma requisição GET para o endpoint `/hello`. Ele loga e retorna o cabeçalho de autorização recebido.
- **Parâmetros**:
  - `@HeaderParam("Authorization") String authorizationHeader`: Extrai o cabeçalho de autorização da requisição HTTP recebida.
- **Retorno**: Retorna o cabeçalho de autorização como uma string, permitindo uma verificação simples do conteúdo do cabeçalho em operações de teste.

### Utilização

Este recurso é especialmente útil em cenários de teste e desenvolvimento, onde desenvolvedores e testadores podem verificar rapidamente a passagem de cabeçalhos de autorização e a aplicação de controles de acesso baseados em roles.


# Collection de teste no ambiente SANDBOX

- Salve o texto abaixo como **DROMOS - TJ.postman_collection.json**
```json
{
    "info": {
        "_postman_id": "ea018af7-ac13-44f6-b8b9-88c53a803a2e",
        "name": "DROMOS - TJ",
        "schema": "https://schema.getpostman.com/json/collection/v2.0.0/collection.json",
        "_exporter_id": "5095999"
    },
    "item": [
        {
            "name": "https://api.caixa.gov.br:8443/sandbox/sigsj/dromos/v1/processo/?numeroprocesso=50193135220204029445",
            "request": {
                "auth": {
                    "type": "oauth2",
                    "oauth2": {
                        "clientSecret": "ecbeee62-ea5a-4135-bc82-a87d7dbc68e5",
                        "clientId": "cli-ext-02292266000180-1",
                        "redirect_uri": "http://localhost:8888/*",
                        "tokenName": "TOKEN_DROMOS_TJ",
                        "accessTokenUrl": "https://logindes.caixa.gov.br/auth/realms/internet/protocol/openid-connect/token",
                        "authUrl": "https://logindes.caixa.gov.br/auth/realms/internet/protocol/openid-connect/auth",
                        "grant_type": "authorization_code",
                        "scope": "openid",
                        "addTokenTo": "header"
                    }
                },
                "method": "POST",
                "header": [
                    {
                        "key": "apikey",
                        "value": "l702ee1b58493444b38369a79684747c80",
                        "type": "text",
                        "uuid": "b3d95578-fa44-4c3a-b850-1bb7d88a10b3"
                    }
                ],
                "body": {
                    "mode": "raw",
                    "raw": "",
                    "options": {
                        "raw": {
                            "language": "json"
                        }
                    }
                },
              "url": {
                "raw": "https://api.caixa.gov.br:8443/sandbox/sigsj/dromos/v1/processo/?numeroprocesso=50193135220204029445",
                "protocol": "https",
                "host": [
                  "api",
                  "caixa",
                  "gov",
                  "br"
                ],
                "port": "8443",
                "path": [
                  "sandbox",
                  "sigsj",
                  "dromos",
                  "v1",
                  "processo",
                  ""
                ],
                "query": [
                  {
                    "key": "numeroprocesso",
                    "value": "50193135220204029445"
                  }
                ]
              }
            },
          "response": []
        }
    ]
}
```





# Atenção

*- Este código é fornecido "como está", sem garantia de qualquer tipo, expressa ou  implícita, incluindo, mas não se limitando às garantias de comercialização,
 adequação a um fim específico e não infração. Em nenhum caso os autores ou  detentores dos direitos autorais serão responsáveis por qualquer reclamação, danos
 ou outra responsabilidade, seja em ação de contrato, delito ou de outra forma,  decorrente de, fora de ou em conexão com o software ou o uso ou outras  negociações no software.*
