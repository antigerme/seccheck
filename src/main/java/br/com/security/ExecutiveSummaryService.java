package br.com.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

/**
 * Gera um resumo executivo do scan em linguagem de negocio, via Claude API.
 *
 * Decisao de arquitetura: usamos o {@link HttpClient} nativo do JDK + Jackson
 * (ja presente no projeto) em vez do SDK oficial da Anthropic. Isso mantem o
 * WAR livre de dependencias adicionais — coerente com a postura
 * dependency-conscious de um scanner de seguranca. A chamada e um unico POST
 * para /v1/messages (tier mais simples: summarizacao), entao o SDK traria
 * pouco beneficio e bastante peso transitivo.
 *
 * A feature so liga quando {@code ANTHROPIC_API_KEY} esta definida. Sem ela,
 * {@link #isEnabled()} retorna false e o painel some na UI.
 *
 * Variaveis de ambiente:
 * <ul>
 *   <li>{@code ANTHROPIC_API_KEY} — chave da API (liga/desliga a feature)</li>
 *   <li>{@code SECCHECK_SUMMARY_MODEL} — modelo Claude (padrao claude-sonnet-4-6)</li>
 *   <li>{@code ANTHROPIC_BASE_URL} — override do endpoint (padrao api.anthropic.com)</li>
 * </ul>
 */
public final class ExecutiveSummaryService {

    private static final String ANTHROPIC_VERSION = "2023-06-01";
    private static final String DEFAULT_MODEL = "claude-sonnet-4-6";
    private static final int MAX_TOKENS = 1024;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(45);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(CONNECT_TIMEOUT)
        .build();

    // Instrucoes estaveis (mesmas em todo scan) — marcadas com cache_control para
    // aproveitar prompt caching da Anthropic. So efetiva acima de ~2K tokens; abaixo
    // disso o cache silenciosamente nao entra, sem prejuizo.
    private static final String SYSTEM_PROMPT = """
        Voce e um analista senior de seguranca da informacao. Recebe os achados de
        uma varredura de dependencias (OWASP Dependency-Check) de um artefato Java
        (.jar/.war/.ear) e produz um RESUMO EXECUTIVO curto para um gestor de TI que
        NAO e especialista tecnico.

        Regras:
        - Escreva de 4 a 7 bullets, em linguagem de negocio (sem jargao tecnico pesado).
        - Liste as vulnerabilidades por prioridade (cite a severidade: critica/alta/media/baixa).
        - Para cada item relevante, explique o impacto em uma frase e a correcao mais simples.
        - Se houver versao de correcao conhecida, mencione-a (ex.: "atualizar para 5.6.1+").
        - Termine com UMA linha de recomendacao de prioridade ("Prioridade: ...").
        - Se nao houver vulnerabilidades, diga isso de forma tranquilizadora em 1-2 linhas.
        - Nao invente CVEs nem dados que nao estejam no input.
        - Responda em texto puro (sem markdown, sem titulos, apenas os bullets com "- ").
        """;

    private ExecutiveSummaryService() {}

    public static boolean isEnabled() {
        String key = System.getenv("ANTHROPIC_API_KEY");
        return key != null && !key.isBlank();
    }

    public static String model() {
        String m = System.getenv("SECCHECK_SUMMARY_MODEL");
        return (m != null && !m.isBlank()) ? m.trim() : DEFAULT_MODEL;
    }

    private static String baseUrl() {
        String u = System.getenv("ANTHROPIC_BASE_URL");
        if (u == null || u.isBlank()) return "https://api.anthropic.com";
        return u.trim().replaceAll("/+$", "");
    }

    /**
     * Chama a Claude API e devolve o texto do resumo. Lanca excecao em qualquer
     * falha (rede, status != 2xx, refusal, corpo inesperado) — o chamador marca
     * o ScanStatus como FAILED.
     */
    public static String generate(Severity.Level severity, int vulnerabilityCount,
                                  List<FixSuggestion> fixes, String langCode) throws Exception {
        String apiKey = System.getenv("ANTHROPIC_API_KEY");
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("ANTHROPIC_API_KEY nao definida.");
        }

        String userContent = buildUserPrompt(severity, vulnerabilityCount, fixes, langCode);
        byte[] body = buildRequestBody(userContent);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl() + "/v1/messages"))
            .timeout(REQUEST_TIMEOUT)
            .header("content-type", "application/json")
            .header("x-api-key", apiKey)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            // Nao logamos o corpo inteiro (pode conter detalhes) — so o status + tipo de erro.
            String errType = safeErrorType(response.body());
            throw new RuntimeException("Claude API retornou HTTP " + status +
                (errType != null ? " (" + errType + ")" : ""));
        }

        JsonNode root = MAPPER.readTree(response.body());
        String stopReason = root.path("stop_reason").asText("");
        if ("refusal".equals(stopReason)) {
            throw new RuntimeException("Claude recusou gerar o resumo (stop_reason=refusal).");
        }

        // content e uma lista de blocos; pegamos o texto do primeiro bloco type=text.
        JsonNode content = root.path("content");
        if (content.isArray()) {
            for (JsonNode block : content) {
                if ("text".equals(block.path("type").asText())) {
                    String text = block.path("text").asText("");
                    if (!text.isBlank()) return text.trim();
                }
            }
        }
        throw new RuntimeException("Resposta da Claude API sem bloco de texto.");
    }

    private static byte[] buildRequestBody(String userContent) {
        ObjectNode bodyNode = MAPPER.createObjectNode();
        bodyNode.put("model", model());
        bodyNode.put("max_tokens", MAX_TOKENS);

        // system como lista de blocos, com cache_control no ultimo (instrucoes estaveis).
        ArrayNode system = bodyNode.putArray("system");
        ObjectNode sysBlock = system.addObject();
        sysBlock.put("type", "text");
        sysBlock.put("text", SYSTEM_PROMPT);
        sysBlock.putObject("cache_control").put("type", "ephemeral");

        ArrayNode messages = bodyNode.putArray("messages");
        ObjectNode userMsg = messages.addObject();
        userMsg.put("role", "user");
        userMsg.put("content", userContent);

        try {
            return MAPPER.writeValueAsBytes(bodyNode);
        } catch (Exception e) {
            throw new RuntimeException("Falha ao serializar corpo da requisicao.", e);
        }
    }

    private static String buildUserPrompt(Severity.Level severity, int vulnerabilityCount,
                                          List<FixSuggestion> fixes, String langCode) {
        StringBuilder sb = new StringBuilder();
        sb.append("Idioma da resposta: ").append(languageInstruction(langCode)).append("\n\n");
        sb.append("Resultado da varredura:\n");
        sb.append("- Severidade maxima encontrada: ").append(severity.name()).append("\n");
        sb.append("- Total de vulnerabilidades (CVEs): ").append(vulnerabilityCount).append("\n\n");

        if (fixes == null || fixes.isEmpty()) {
            sb.append("Nenhuma dependencia vulneravel com correcao mapeada.\n");
        } else {
            sb.append("Dependencias afetadas e correcoes sugeridas:\n");
            for (FixSuggestion f : fixes) {
                sb.append("- ").append(f.groupId).append(":").append(f.artifactId)
                  .append(" (atual ").append(f.currentVersion)
                  .append(", corrigir para ").append(f.fixedVersion).append("+)")
                  .append(" | severidade ").append(f.severity.name())
                  .append(" | CVEs: ").append(String.join(", ", f.cves))
                  .append("\n");
            }
        }
        return sb.toString();
    }

    /** Mapeia o codigo de idioma da UI para uma instrucao explicita no prompt. */
    private static String languageInstruction(String langCode) {
        if (langCode == null) return "portugues do Brasil";
        String lc = langCode.toLowerCase(Locale.ROOT);
        if (lc.startsWith("en")) return "ingles (English)";
        if (lc.startsWith("es")) return "espanhol (Espanol)";
        return "portugues do Brasil";
    }

    private static String safeErrorType(String body) {
        try {
            return MAPPER.readTree(body).path("error").path("type").asText(null);
        } catch (Exception e) {
            return null;
        }
    }
}
