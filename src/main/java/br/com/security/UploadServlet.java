package br.com.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Future;

@WebServlet(name = "UploadServlet", urlPatterns = {"/api/scan"}, asyncSupported = true)
@MultipartConfig(
    fileSizeThreshold = 1024 * 1024 * 10,           // 10 MB: threshold antes de ir para o disco
    // [SEC] Limite final aplicado em app via DPCK_MAX_FILE_MB. O teto absoluto do
    // container (2 GB) protege contra clientes mal-comportados que ignoram o erro inicial.
    maxFileSize      = 1024L * 1024 * 1024 * 2,
    maxRequestSize   = 1024L * 1024 * 1024 * 2 + 1024 * 1024
)
public class UploadServlet extends HttpServlet {

    private static final List<String> ACCEPTED_EXTENSIONS = List.of(".jar", ".war", ".ear");

    @Override
    public void init() throws ServletException {
        super.init();
        LogUtils.info("UploadServlet inicializado (pool gerenciado pelo AppContextListener).");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LogUtils.info("POST /api/scan recebido.");

        Part filePart;
        try {
            filePart = request.getPart("file");
        } catch (Exception e) {
            // IllegalStateException quando excede maxRequestSize do container
            Metrics.uploadsRejected.incrementAndGet();
            LogUtils.warn("Multipart invalido: " + e.getMessage());
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST,
                "Requisicao multipart invalida ou arquivo excede o teto absoluto.");
            return;
        }

        if (filePart == null || filePart.getSize() == 0) {
            Metrics.uploadsRejected.incrementAndGet();
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST, "Arquivo invalido ou ausente.");
            return;
        }

        // Limite configuravel via DPCK_MAX_FILE_MB (padrao: 500 MB)
        long maxFileMb = AppContextListener.getEnvLong("DPCK_MAX_FILE_MB", 500L);
        long maxFileBytes = maxFileMb * 1024L * 1024L;

        if (filePart.getSize() > maxFileBytes) {
            Metrics.uploadsRejected.incrementAndGet();
            LogUtils.warn("Upload rejeitado: " + (filePart.getSize() / 1024 / 1024) +
                " MB excede limite de " + maxFileMb + " MB.");
            JsonResponse.writeError(response, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                "Arquivo excede o limite de " + maxFileMb + " MB.");
            return;
        }

        // [SEC] Sanitiza o nome do arquivo:
        // 1. Trata getSubmittedFileName() == null (Content-Disposition sem filename)
        // 2. Extrai somente o nome base (descarta separadores de diretorio -> previne path traversal)
        // 3. Compara extensao case-insensitive
        String submittedFileName = filePart.getSubmittedFileName();
        if (submittedFileName == null) submittedFileName = "";
        submittedFileName = new File(submittedFileName).getName();

        String lower = submittedFileName.toLowerCase(Locale.ROOT);
        String extension = null;
        for (String ext : ACCEPTED_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                extension = ext;
                break;
            }
        }
        if (extension == null) {
            Metrics.uploadsRejected.incrementAndGet();
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST,
                "Apenas arquivos .jar, .war e .ear sao suportados.");
            return;
        }

        // [SEC] Fila cheia -> 503 para evitar DoS por upload
        if (AppContextListener.isQueueFull()) {
            Metrics.uploadsRejected.incrementAndGet();
            LogUtils.warn("Fila cheia (" + AppContextListener.queueSize() + " scans). Rejeitando upload.");
            JsonResponse.writeError(response, HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                "Servidor sobrecarregado. Tente novamente em alguns minutos.");
            return;
        }

        String scanId = UUID.randomUUID().toString();
        LogUtils.info("Gerado Scan ID: " + scanId + " (origem: " + submittedFileName + ", " +
            (filePart.getSize() / 1024 / 1024) + " MB)");

        Path tempDir = Files.createTempDirectory("dpck_" + scanId);
        // [SEC] Nome fixo baseado em scanId: o nome submetido pelo cliente nao
        // chega ao disco, evitando qualquer dependencia em caracteres do nome.
        Path uploadedFile = tempDir.resolve("target-" + scanId + extension);
        String originalName = submittedFileName; // guardado so para log

        try (var inputStream = filePart.getInputStream()) {
            Files.copy(inputStream, uploadedFile, StandardCopyOption.REPLACE_EXISTING);
            LogUtils.debug("Arquivo gravado em " + uploadedFile);
        } catch (Exception e) {
            Metrics.uploadsRejected.incrementAndGet();
            LogUtils.error("Erro ao gravar arquivo do scan " + scanId, e);
            FileUtils.deleteDirectoryRecursively(tempDir);
            JsonResponse.writeError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                "Erro interno ao salvar o arquivo.");
            return;
        }

        // [SEC] Valida magic bytes ZIP — protege contra extensao falsa
        if (!FileUtils.isZipMagic(uploadedFile)) {
            Metrics.uploadsRejected.incrementAndGet();
            LogUtils.warn("Arquivo " + originalName + " nao e um ZIP/JAR/WAR/EAR valido. Descartando.");
            FileUtils.deleteDirectoryRecursively(tempDir);
            JsonResponse.writeError(response, HttpServletResponse.SC_BAD_REQUEST,
                "O arquivo enviado nao parece ser um JAR/WAR/EAR valido.");
            return;
        }

        ScanStatus status = new ScanStatus(tempDir);
        ScanManager.put(scanId, status);
        Metrics.uploadsAccepted.incrementAndGet();

        // Responde imediatamente com o Scan ID
        ObjectNode body = JsonResponse.node();
        body.put("scanId", scanId);
        body.put("message", "Varredura iniciada");
        JsonResponse.write(response, HttpServletResponse.SC_ACCEPTED, body);
        response.getWriter().flush();

        // Tarefa em background
        Future<?> task = AppContextListener.scanExecutor().submit(() -> runScan(scanId, status, uploadedFile, tempDir));
        status.setTask(task);
    }

    private void runScan(String scanId, ScanStatus status, Path uploadedFile, Path tempDir) {
        long start = System.currentTimeMillis();
        try {
            status.update(ScanStatus.State.RUNNING, "Preparando analise...");
            status.updateProgress(5, "Iniciando motor de analise...");
            DependencyCheckRunner runner = new DependencyCheckRunner();
            Path reportHtml = runner.runScan(uploadedFile, tempDir, status);

            if (status.isCancelRequested()) {
                LogUtils.info("Scan " + scanId + " interrompido por cancelamento.");
                return;
            }

            if (reportHtml != null && Files.exists(reportHtml)) {
                LogUtils.info("Scan " + scanId + " concluido em " + (System.currentTimeMillis() - start) + "ms.");

                // Libera o disco assim que o scan termina: o JAR/WAR/EAR ja foi analisado e
                // o relatorio HTML ja esta gravado. So o relatorio precisa sobreviver ate
                // o cliente baixar (ou o TTL do ScanManager expirar). Em uploads grandes
                // (centenas de MB) isso evita acumulo significativo no /tmp.
                try {
                    long bytes = Files.size(uploadedFile);
                    Files.deleteIfExists(uploadedFile);
                    LogUtils.info("Scan " + scanId + ": upload removido apos analise (" +
                        (bytes / 1024 / 1024) + " MB liberados).");
                } catch (IOException ioe) {
                    // Nao critico: o TTL do ScanManager limpa o tempDir inteiro depois.
                    LogUtils.warn("Falha ao remover upload de " + scanId + ": " + ioe.getMessage());
                }

                status.setCompleted(reportHtml);
                Metrics.scansCompleted.incrementAndGet();
                Metrics.totalScanDurationMs.addAndGet(System.currentTimeMillis() - start);
            } else {
                status.update(ScanStatus.State.ERROR, "O relatorio HTML nao foi gerado.");
                Metrics.scansFailed.incrementAndGet();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            LogUtils.info("Scan " + scanId + " interrompido.");
            // ja foi marcado como CANCELLED pelo ScanManager.cancel
        } catch (Exception e) {
            LogUtils.error("Falha no scan " + scanId, e);
            status.update(ScanStatus.State.ERROR, "Erro interno durante a varredura. Contate o administrador.");
            FileUtils.deleteDirectoryRecursively(tempDir);
            Metrics.scansFailed.incrementAndGet();
        }
    }

    @Override
    public void destroy() {
        // Shutdown do pool centralizado no AppContextListener.
        super.destroy();
    }
}
