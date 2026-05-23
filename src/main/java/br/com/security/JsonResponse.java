package br.com.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Padroniza a montagem de respostas JSON da aplicacao usando Jackson em todos os
 * endpoints (substitui concatenacao manual de strings JSON, que e fragil para
 * injecao de aspas e caracteres unicode em mensagens dinamicas).
 */
public final class JsonResponse {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonResponse() {}

    public static ObjectNode node() {
        return MAPPER.createObjectNode();
    }

    /** Escreve um node JSON com o status HTTP indicado, sempre sem cache. */
    public static void write(HttpServletResponse response, int status, ObjectNode body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        MAPPER.writeValue(response.getWriter(), body);
    }

    /** Atalho para respostas de erro: {"error": "<msg>"}. */
    public static void writeError(HttpServletResponse response, int status, String message) throws IOException {
        ObjectNode body = node();
        body.put("error", message);
        write(response, status, body);
    }
}
