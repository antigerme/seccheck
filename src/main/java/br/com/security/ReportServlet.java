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

@WebServlet(name = "ReportServlet", urlPatterns = {"/api/report"})
public class ReportServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        if (id == null || id.isBlank()) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Parametro 'id' ausente.");
            return;
        }
        // [SEC] Valida formato UUID antes de consultar o ScanManager
        try {
            UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Scan ID malformado.");
            return;
        }

        ScanStatus status = ScanManager.get(id);
        if (status == null || status.getState() != ScanStatus.State.COMPLETED) {
            JsonResponse.writeError(response, HttpServletResponse.SC_NOT_FOUND,
                "Relatorio nao encontrado, varredura nao concluida ou relatorio ja foi baixado.");
            return;
        }

        Path reportPath = status.getReportPath();
        if (reportPath == null || !Files.exists(reportPath)) {
            JsonResponse.writeError(response, HttpServletResponse.SC_NOT_FOUND, "Arquivo de relatorio perdido no servidor.");
            return;
        }

        // [SEC] Forcamos download (attachment) ao inves de renderizar o HTML no mesmo contexto.
        // Isso isola o relatorio do contexto da aplicacao, evitando XSS via conteudo do relatorio.
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=\"dependency-check-report.html\"");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Cache-Control", "no-store");
        response.setContentLengthLong(Files.size(reportPath));

        // Politica "no re-download" estrita: o relatorio e descartado independente
        // do resultado do streaming. Como o front-end desabilita o botao de download
        // logo apos o primeiro clique, manter um relatorio "de reserva" via TTL nao
        // ajudaria o usuario — entao removemos no finally. Unica excecao: HEAD
        // requests (probes/monitoring) nao consomem o scan.
        boolean isHead = "HEAD".equalsIgnoreCase(request.getMethod());
        try (InputStream in = Files.newInputStream(reportPath);
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            out.flush();
        } catch (IOException ioe) {
            LogUtils.warn("Download interrompido para scan " + id + ": " + ioe.getMessage());
            throw ioe;
        } finally {
            if (!isHead) {
                LogUtils.info("Removendo scan " + id + " apos download (politica no-re-download).");
                FileUtils.deleteDirectoryRecursively(status.getWorkDir());
                ScanManager.remove(id);
            }
        }
    }
}
