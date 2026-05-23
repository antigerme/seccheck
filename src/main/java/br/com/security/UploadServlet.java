package br.com.security;

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
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

@WebServlet(name = "UploadServlet", urlPatterns = {"/api/scan"}, asyncSupported = true)
@MultipartConfig(
    fileSizeThreshold = 1024 * 1024 * 10,           // 10 MB: threshold antes de ir para o disco
    maxFileSize      = 1024L * 1024 * 1024 * 2,     // 2 GB: teto absoluto (seguranca do container)
    maxRequestSize   = 1024L * 1024 * 1024 * 2 + 1024 * 1024 // 2 GB + 1 MB de overhead
)
public class UploadServlet extends HttpServlet {

    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    @Override
    public void init() throws ServletException {
        super.init();
        LogUtils.info("UploadServlet inicializado com Pool Fixo de 4 Threads.");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        LogUtils.info("=== Nova requisicao POST recebida em /api/scan ===");
        Part filePart = request.getPart("file");

        if (filePart == null || filePart.getSize() == 0) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.getWriter().write("{\"error\": \"Arquivo invalido ou ausente.\"}");
            return;
        }

        // Limite configuravel via variavel de ambiente DPCK_MAX_FILE_MB (padrao: 500 MB)
        long maxFileMb;
        try {
            String envMax = System.getenv("DPCK_MAX_FILE_MB");
            maxFileMb = (envMax != null && !envMax.isBlank()) ? Long.parseLong(envMax.trim()) : 500L;
        } catch (NumberFormatException e) {
            LogUtils.info("DPCK_MAX_FILE_MB com valor invalido. Usando padrao de 500 MB.");
            maxFileMb = 500L;
        }
        long maxFileBytes = maxFileMb * 1024 * 1024;

        if (filePart.getSize() > maxFileBytes) {
            LogUtils.info("Upload rejeitado: arquivo com " + (filePart.getSize() / 1024 / 1024) +
                " MB excede o limite de " + maxFileMb + " MB (DPCK_MAX_FILE_MB).");
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            response.getWriter().write("{\"error\": \"Arquivo excede o limite de " + maxFileMb + " MB.\"}");
            return;
        }

        String submittedFileName = filePart.getSubmittedFileName();
        // [SEC] Sanitiza o nome do arquivo para evitar Path Traversal (ex: "../../etc/passwd.jar")
        // Extrai somente o nome base, descartando qualquer separador de diretorio
        submittedFileName = new File(submittedFileName).getName();
        if (submittedFileName.isBlank() ||
            (!submittedFileName.endsWith(".jar") && !submittedFileName.endsWith(".war"))) {
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\": \"Apenas arquivos .jar e .war sao suportados.\"}");
            return;
        }

        // [SEC] Rejeita se a fila de processamento estiver cheia para evitar DoS por upload
        ThreadPoolExecutor pool = (ThreadPoolExecutor) executor;
        if (pool.getQueue().size() >= 10) {
            LogUtils.info("Fila cheia (" + pool.getQueue().size() + " scans pendentes). Rejeitando upload.");
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.getWriter().write("{\"error\": \"Servidor sobrecarregado. Tente novamente em alguns minutos.\"}");
            return;
        }

        String scanId = UUID.randomUUID().toString();
        LogUtils.info("Gerado Scan ID: " + scanId);

        Path tempDir = Files.createTempDirectory("dpck_" + scanId);
        Path uploadedFile = tempDir.resolve(submittedFileName);
        
        try (var inputStream = filePart.getInputStream()) {
            Files.copy(inputStream, uploadedFile, StandardCopyOption.REPLACE_EXISTING);
            LogUtils.info("Arquivo " + submittedFileName + " gravado com sucesso.");
        } catch (Exception e) {
            LogUtils.error("Erro ao gravar o arquivo.", e);
            // [SEC] Garante limpeza do diretorio temporario em caso de falha no upload
            FileUtils.deleteDirectoryRecursively(tempDir.toFile());
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\": \"Erro interno ao salvar o arquivo.\"}" );
            return;
        }

        // Criar e registrar o status inicial
        ScanStatus status = new ScanStatus();
        ScanManager.put(scanId, status);

        // Responder imediatamente o Scan ID
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(HttpServletResponse.SC_ACCEPTED);
        response.getWriter().write("{\"scanId\": \"" + scanId + "\", \"message\": \"Varredura iniciada\"}");
        response.getWriter().flush();

        // Tarefa em background
        executor.submit(() -> {
            try {
                status.update(ScanStatus.State.RUNNING, "Preparando analise...");
                status.updateProgress(5, "Iniciando motor de analise...");
                DependencyCheckRunner runner = new DependencyCheckRunner();
                Path reportHtml = runner.runScan(uploadedFile, tempDir, status);
                
                if (reportHtml != null && Files.exists(reportHtml)) {
                    LogUtils.info("Scan " + scanId + " concluido com sucesso.");
                    status.setCompleted(reportHtml, tempDir);
                } else {
                    status.update(ScanStatus.State.ERROR, "O relatorio HTML nao foi gerado.");
                }
            } catch (Exception e) {
                LogUtils.error("Falha no processo de scan ID " + scanId, e);
                // [SEC] Mensagem generica para o cliente (sem expor detalhes internos/stack trace)
                status.update(ScanStatus.State.ERROR, "Erro interno durante a varredura. Contate o administrador.");
                // Limpa o diretorio temporario quando da erro fatal (sem relatorio para servir)
                FileUtils.deleteDirectoryRecursively(tempDir.toFile());
                ScanManager.remove(scanId);
            }
        });
    }


    @Override
    public void destroy() {
        executor.shutdown();
        super.destroy();
    }
}
