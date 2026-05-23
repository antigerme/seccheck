package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.utils.Settings;

import java.nio.file.Path;

public class DependencyCheckRunner {

    public static Settings createSettings() {
        LogUtils.info("DependencyCheckRunner.createSettings() - Instanciando Settings...");
        Settings settings = new Settings();
        
        String dataDir = System.getenv("DPCK_DATA_DIR");
        if (dataDir == null || dataDir.isBlank()) {
            dataDir = System.getProperty("user.home") + "/.dependency-check/data";
            LogUtils.info("DPCK_DATA_DIR nao definido. Usando diretorio padrao: " + dataDir);
        } else {
            LogUtils.info("DPCK_DATA_DIR definido: " + dataDir);
        }
        settings.setString("data.directory", dataDir);

        String nvdApiKey = System.getenv("NVD_API_KEY");
        if (nvdApiKey != null && !nvdApiKey.isBlank()) {
            LogUtils.info("NVD_API_KEY configurada. Injetando nas propriedades.");
            settings.setString("nvd.api.key", nvdApiKey);
        } else {
            LogUtils.info("AVISO: NVD_API_KEY NAO definida.");
        }

        String ossUser = System.getenv("OSS_INDEX_USER");
        String ossPass = System.getenv("OSS_INDEX_PASS");
        
        // Garante explicitamente que o analisador do OSS Index sera executado
        LogUtils.info("Forcando ativacao do analisador OSS Index na Engine.");
        settings.setBoolean("analyzer.ossindex.enabled", true);
        
        if (ossUser != null && !ossUser.isBlank() && ossPass != null && !ossPass.isBlank()) {
            LogUtils.info("OSS_INDEX credentials configuradas.");
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
        
        LogUtils.info("Configurando 'auto.update' para false para esta varredura (evitar conflito/lentidao).");
        settings.setBoolean("auto.update", false);
        
        LogUtils.info("Settings montado com sucesso.");
        return settings;
    }

    public Path runScan(Path targetFile, Path workDir, ScanStatus status) throws Exception {
        Path reportHtml = workDir.resolve("dependency-check-report.html");
        
        LogUtils.info("runScan iniciado para arquivo: " + targetFile.toString());
        status.updateProgress(10, "Aguardando acesso ao banco de dados...");

        LogUtils.info("Aguardando ReadLock do banco de dados (em caso de update paralelo)...");
        DatabaseUpdater.DB_LOCK.readLock().lock();
        LogUtils.info("ReadLock ADQUIRIDO.");
        
        try {
            status.updateProgress(15, "Preparando configuracoes do motor de analise...");
            Settings settings = createSettings();

            status.updateProgress(20, "Iniciando motor OWASP Dependency-Check...");
            LogUtils.info("Iniciando instancia da Engine do Dependency-Check...");
            try (Engine engine = new Engine(settings)) {
                LogUtils.info("Engine instanciada. Adicionando arquivo para scan: " + targetFile.toFile().getAbsolutePath());
                engine.scan(targetFile.toFile());
                
                status.updateProgress(30, "Analisando dependencias encontradas...");
                LogUtils.info("Iniciando analyzeDependencies() do motor...");
                engine.analyzeDependencies();
                LogUtils.info("analyzeDependencies() concluido.");
                
                status.updateProgress(80, "Gerando relatorio HTML...");
                LogUtils.info("Gerando relatorio HTML em: " + workDir.toFile().getAbsolutePath());
                engine.writeReports("SecCheck Analysis", workDir.toFile(), "HTML", null);
                
                status.updateProgress(95, "Finalizando...");
                LogUtils.info("Relatorio final gerado: " + reportHtml.toAbsolutePath());
            } catch (Exception ex) {
                LogUtils.error("Erro fatal capturado durante o scan/engine.", ex);
                throw ex;
            } finally {
                LogUtils.info("Limpando settings (cleanup).");
                settings.cleanup();
            }
        } finally {
            LogUtils.info("Liberando ReadLock do banco de dados.");
            DatabaseUpdater.DB_LOCK.readLock().unlock();
        }

        return reportHtml;
    }
}
