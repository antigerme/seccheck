package br.com.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.UUID;

@WebServlet(name = "StatusServlet", urlPatterns = {"/api/status"})
public class StatusServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        if (id == null || id.isBlank()) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Parametro 'id' ausente.");
            return;
        }

        // [SEC] Valida formato UUID. Falha cedo para qualquer entrada malformada.
        try {
            UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Scan ID malformado.");
            return;
        }

        ScanStatus status = ScanManager.get(id);
        if (status == null) {
            JsonResponse.writeError(response, HttpServletResponse.SC_NOT_FOUND, "Scan ID nao encontrado");
            return;
        }

        ObjectNode node = JsonResponse.node();
        node.put("state", status.getState().name());
        node.put("message", status.getMessage());
        node.put("progress", status.getProgress());
        // Soh inclui resultado de severidade quando ja finalizou
        if (status.getState() == ScanStatus.State.COMPLETED) {
            node.put("severity", status.getSeverity().name());
            node.put("vulnerabilityCount", status.getVulnerabilityCount());
        }
        JsonResponse.write(response, HttpServletResponse.SC_OK, node);
    }
}
