package br.com.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Map;

/**
 * Expoe metadados do build (versao, commit, branch, timestamp) lidos do
 * MANIFEST.MF. Util em producao para confirmar qual artefato esta no pod
 * sem precisar entrar no container e abrir o WAR.
 */
@WebServlet(name = "VersionServlet", urlPatterns = {"/api/version"})
public class VersionServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        ObjectNode body = JsonResponse.node();
        for (Map.Entry<String, String> entry : BuildInfo.attributes().entrySet()) {
            body.put(entry.getKey(), entry.getValue());
        }
        body.put("summary", BuildInfo.summary());
        JsonResponse.write(response, HttpServletResponse.SC_OK, body);
    }
}
