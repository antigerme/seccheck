package br.com.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.UUID;

/**
 * Retorna o resumo executivo (gerado por Claude) de um scan.
 *
 * Estados possiveis em {@code state}: DISABLED, PENDING, GENERATING, READY, FAILED.
 * Quando READY, o campo {@code summary} traz o texto. O front-end faz polling
 * deste endpoint enquanto GENERATING.
 *
 * Se a feature estiver globalmente desligada (sem ANTHROPIC_API_KEY), retorna
 * 200 com state=DISABLED (nao 503) — assim a UI simplesmente nao mostra o painel,
 * sem tratar como erro.
 */
@WebServlet(name = "SummaryServlet", urlPatterns = {"/api/summary"})
public class SummaryServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        if (id == null || id.isBlank()) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Parametro 'id' ausente.");
            return;
        }
        try {
            UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Scan ID malformado.");
            return;
        }

        ScanStatus status = ScanManager.get(id);
        if (status == null) {
            JsonResponse.writeError(response, HttpServletResponse.SC_NOT_FOUND, "Scan ID nao encontrado.");
            return;
        }

        ObjectNode node = JsonResponse.node();
        ScanStatus.SummaryState st = status.getSummaryState();
        node.put("state", st.name());
        if (st == ScanStatus.SummaryState.READY) {
            node.put("summary", status.getExecutiveSummary());
            node.put("model", ExecutiveSummaryService.model());
            node.put("generatedAt", status.getSummaryGeneratedAt());
        }
        JsonResponse.write(response, HttpServletResponse.SC_OK, node);
    }
}
