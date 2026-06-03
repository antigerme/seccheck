package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.utils.Settings;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class DependencyCheckRunner {

    public static Settings createSettings() {
        LogUtils.debug("createSettings() - instanciando Settings");
        Settings settings = new Settings();

        String dataDir = System.getenv("DPCK_DATA_DIR");
        if (dataDir == null || dataDir.isBlank()) {
            dataDir = System.getProperty("user.home") + "/.dependency-check/data";
            LogUtils.info("DPCK_DATA_DIR nao definido. Usando diretorio padrao: " + dataDir);
        } else {
            LogUtils.debug("DPCK_DATA_DIR: " + dataDir);
        }
        settings.setString("data.directory", dataDir);

        String nvdApiKey = System.getenv("NVD_API_KEY");
        if (nvdApiKey != null && !nvdApiKey.isBlank()) {
            LogUtils.debug("NVD_API_KEY configurada.");
            settings.setString("nvd.api.key", nvdApiKey);
        } else {
            LogUtils.warn("NVD_API_KEY NAO definida. Sujeito a rate limit do governo americano.");
        }

        String ossUser = System.getenv("OSS_INDEX_USER");
        String ossPass = System.getenv("OSS_INDEX_PASS");

        settings.setBoolean("analyzer.ossindex.enabled", true);
        LogUtils.debug("Analisador OSS Index ativado.");

        if (ossUser != null && !ossUser.isBlank() && ossPass != null && !ossPass.isBlank()) {
            settings.setString("analyzer.ossindex.user", ossUser);
            settings.setString("analyzer.ossindex.password", ossPass);
        }

        String proxyServer = System.getenv("HTTP_PROXY_SERVER");
        String proxyPort = System.getenv("HTTP_PROXY_PORT");
        if (proxyServer != null && !proxyServer.isBlank()) {
            LogUtils.info("HTTP_PROXY configurado: " + proxyServer + ":" + proxyPort);
            settings.setString("proxy.server", proxyServer);
            if (proxyPort != null && !proxyPort.isBlank()) {
                settings.setString("proxy.port", proxyPort);
            }
        }

        settings.setBoolean("auto.update", false);
        return settings;
    }

    public Path runScan(Path targetFile, Path workDir, ScanStatus status) throws Exception {
        Path reportHtml = workDir.resolve("dependency-check-report.html");

        LogUtils.info("runScan iniciado: " + targetFile);
        status.updateProgress(10, "Aguardando acesso ao banco de dados...");

        checkCancellation(status);

        LogUtils.debug("Aguardando ReadLock (em caso de update paralelo).");
        DatabaseUpdater.DB_LOCK.readLock().lock();
        LogUtils.debug("ReadLock adquirido.");

        // Smoother de progresso: avanca lentamente entre checkpoints conhecidos
        // para o cliente nao ficar parado em 30% por minutos seguidos.
        ScheduledExecutorService smoother = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dpck-progress-smoother");
            t.setDaemon(true);
            return t;
        });
        int[] target = {30}; // alvo controlado pelas fases abaixo
        ScheduledFuture<?> smoothing = smoother.scheduleAtFixedRate(() -> {
            int current = status.getProgress();
            if (current < target[0] - 1) {
                // Avanca 1pp a cada 2s ate o target
                status.updateProgress(current + 1, status.getMessage());
            }
        }, 2, 2, TimeUnit.SECONDS);

        try {
            status.updateProgress(15, "Preparando configuracoes do motor...");
            checkCancellation(status);
            Settings settings = createSettings();

            status.updateProgress(20, "Iniciando motor OWASP Dependency-Check...");
            try (Engine engine = new Engine(settings)) {
                checkCancellation(status);
                LogUtils.info("Engine instanciada. Submetendo arquivo: " + targetFile.getFileName());
                engine.scan(targetFile.toFile());

                target[0] = 70;
                status.updateProgress(30, "Analisando dependencias encontradas...");
                checkCancellation(status);
                engine.analyzeDependencies();
                LogUtils.info("analyzeDependencies() concluido.");

                target[0] = 90;
                status.updateProgress(80, "Gerando relatorio HTML...");
                checkCancellation(status);
                engine.writeReports("SecCheck Analysis", workDir.toFile(), "HTML", null);

                // Captura severidade pior + total de CVEs + sugestoes de fix + findings detalhadas
                // (estas ultimas alimentam o diff scan no front-end).
                Severity.Level worst = Severity.worstOf(engine);
                int totalVulns = 0;
                for (var dep : engine.getDependencies()) totalVulns += dep.getVulnerabilities().size();
                var fixes = FixSuggester.suggest(engine);
                var findings = FindingsExtractor.extract(engine);
                status.setScanResult(worst, totalVulns, fixes, findings);
                LogUtils.info("Severidade do scan: " + worst + " (" + totalVulns + " CVE(s) total, " +
                    fixes.size() + " sugestao(oes) de fix, " + findings.size() + " finding(s)).");

                status.updateProgress(95, "Finalizando...");
                LogUtils.info("Relatorio gerado: " + reportHtml.toAbsolutePath());
            } catch (Exception ex) {
                LogUtils.error("Erro durante o scan/engine.", ex);
                throw ex;
            } finally {
                settings.cleanup();
            }
        } finally {
            smoothing.cancel(true);
            smoother.shutdownNow();
            DatabaseUpdater.DB_LOCK.readLock().unlock();
            LogUtils.debug("ReadLock liberado.");
        }

        return reportHtml;
    }

    /**
     * Localiza o arquivo CycloneDX gerado pela Engine no workDir.
     * O nome varia entre versoes do dependency-check (ja vimos
     * {@code dependency-check-report.cyclonedx.json}, {@code bom.json},
     * etc.), entao buscamos por pattern em vez de assumir um nome fixo.
     */
    private Path locateSbom(Path workDir) {
        try (var stream = Files.list(workDir)) {
            return stream
                .filter(Files::isRegularFile)
                .filter(p -> {
                    String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                    if (!name.endsWith(".json")) return false;
                    return name.contains("cyclonedx") || name.contains("bom");
                })
                .findFirst()
                .orElse(null);
        } catch (Exception e) {
            LogUtils.debug("Falha ao listar workDir para SBOM: " + e);
            return null;
        }
    }

    private void checkCancellation(ScanStatus status) throws InterruptedException {
        if (status.isCancelRequested() || Thread.currentThread().isInterrupted()) {
            throw new InterruptedException("Scan cancelado pelo usuario.");
        }
    }
}
