package br.com.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Entrega o SBOM CycloneDX (formato JSON) gerado durante o scan.
 *
 * Politica "no re-download" identica ao {@link ReportServlet}: apos o stream
 * concluir, o arquivo do SBOM e deletado. O workDir do scan e descartado
 * apenas quando todos os formatos consumiveis (HTML + SBOM) ja foram
 * baixados — assim o usuario pode pegar HTML e SBOM em qualquer ordem sem
 * que o primeiro download invalide o segundo.
 */
@WebServlet(name = "SbomServlet", urlPatterns = {"/api/sbom"})
public class SbomServlet extends HttpServlet {

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
        if (status == null || status.getState() != ScanStatus.State.COMPLETED) {
            JsonResponse.writeError(response, HttpServletResponse.SC_NOT_FOUND,
                "SBOM nao encontrado, varredura nao concluida ou SBOM ja foi baixado.");
            return;
        }

        Path sbomPath = status.getSbomPath();
        if (sbomPath == null || !Files.exists(sbomPath)) {
            JsonResponse.writeError(response, HttpServletResponse.SC_NOT_FOUND,
                "Arquivo SBOM nao disponivel para este scan.");
            return;
        }

        response.setContentType("application/vnd.cyclonedx+json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=\"sbom-cyclonedx.json\"");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Cache-Control", "no-store");
        response.setContentLengthLong(Files.size(sbomPath));

        boolean isHead = "HEAD".equalsIgnoreCase(request.getMethod());
        try (InputStream in = Files.newInputStream(sbomPath);
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);
            out.flush();
        } catch (IOException ioe) {
            LogUtils.warn("Download SBOM interrompido para scan " + id + ": " + ioe.getMessage());
            throw ioe;
        } finally {
            if (!isHead) {
                LogUtils.info("Removendo SBOM do scan " + id + " apos download (politica no-re-download).");
                ScanCleanup.afterFileConsumed(id, status, sbomPath);
            }
        }
    }
}
