package br.com.security;

import com.fasterxml.jackson.databind.node.ArrayNode;
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
        // Soh inclui resultado de severidade + fix suggestions quando ja finalizou
        if (status.getState() == ScanStatus.State.COMPLETED) {
            node.put("severity", status.getSeverity().name());
            node.put("vulnerabilityCount", status.getVulnerabilityCount());

            ArrayNode fixes = node.putArray("fixSuggestions");
            for (FixSuggestion fs : status.getFixSuggestions()) {
                ObjectNode f = fixes.addObject();
                f.put("groupId", fs.groupId);
                f.put("artifactId", fs.artifactId);
                f.put("currentVersion", fs.currentVersion);
                f.put("fixedVersion", fs.fixedVersion);
                f.put("severity", fs.severity.name());
                ArrayNode cves = f.putArray("cves");
                for (String c : fs.cves) cves.add(c);
                f.put("pomSnippet", fs.pomSnippet);
            }

            // Findings completas (1 entrada por par dep+CVE). Cliente usa pra computar
            // o diff scan contra um baseline guardado em memoria/localStorage.
            ArrayNode findings = node.putArray("findings");
            for (ScanFinding sf : status.getFindings()) {
                ObjectNode f = findings.addObject();
                f.put("groupId", sf.groupId);
                f.put("artifactId", sf.artifactId);
                f.put("version", sf.version);
                f.put("cveName", sf.cveName);
                f.put("severity", sf.severity.name());
                f.put("cvssScore", sf.cvssScore);
            }
        }
        JsonResponse.write(response, HttpServletResponse.SC_OK, node);
    }
}
