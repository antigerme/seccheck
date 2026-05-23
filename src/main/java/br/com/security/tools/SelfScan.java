package br.com.security.tools;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;

/**
 * Self-scan do WAR final usando dependency-check-core diretamente — a mesma
 * biblioteca que o {@code DependencyCheckRunner} usa em producao. Como o
 * range {@code [10.0.0,)} no pom faz o Maven puxar sempre a versao mais
 * recente da biblioteca, esta classe escaneia com a engine atualizada a cada
 * build, sem depender do {@code dependency-check-maven} (que precisa de
 * versao pinada).
 *
 * Invocada pelo profile {@code self-scan} via {@code exec-maven-plugin}:
 *   mvn verify -Pself-scan
 *
 * Argumentos:
 *   args[0] = caminho do WAR
 *   args[1] = diretorio de saida (onde o relatorio HTML/JSON sera gerado)
 */
public final class SelfScan {

    private SelfScan() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Uso: SelfScan <war-path> <output-dir>");
            System.exit(2);
        }
        File war = new File(args[0]);
        File outputDir = new File(args[1]);

        if (!war.exists()) {
            System.err.println("[SelfScan] WAR nao encontrado: " + war.getAbsolutePath());
            System.exit(2);
        }
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            System.err.println("[SelfScan] Falha ao criar diretorio de saida: " + outputDir.getAbsolutePath());
            System.exit(2);
        }

        Settings settings = new Settings();
        String dataDir = System.getenv("DPCK_DATA_DIR");
        if (dataDir == null || dataDir.isBlank()) {
            dataDir = System.getProperty("user.home") + "/.dependency-check/data";
            System.out.println("[SelfScan] DPCK_DATA_DIR nao definido. Usando: " + dataDir);
        }
        settings.setString("data.directory", dataDir);

        String nvdApiKey = System.getenv("NVD_API_KEY");
        if (nvdApiKey != null && !nvdApiKey.isBlank()) {
            settings.setString("nvd.api.key", nvdApiKey);
            System.out.println("[SelfScan] NVD_API_KEY configurada.");
        } else {
            System.out.println("[SelfScan] AVISO: NVD_API_KEY nao definida. Sujeito a rate limit do governo americano.");
        }

        String proxyServer = System.getenv("HTTP_PROXY_SERVER");
        String proxyPort = System.getenv("HTTP_PROXY_PORT");
        if (proxyServer != null && !proxyServer.isBlank()) {
            settings.setString("proxy.server", proxyServer);
            if (proxyPort != null && !proxyPort.isBlank()) {
                settings.setString("proxy.port", proxyPort);
            }
        }

        settings.setBoolean("analyzer.ossindex.enabled", true);
        settings.setBoolean("auto.update", true);

        int totalCves = 0;
        int vulnerableDeps = 0;
        try (Engine engine = new Engine(settings)) {
            System.out.println("[SelfScan] Atualizando base NVD...");
            engine.doUpdates();

            System.out.println("[SelfScan] Escaneando: " + war.getAbsolutePath());
            engine.scan(war);
            engine.analyzeDependencies();

            System.out.println("[SelfScan] Gerando relatorio em: " + outputDir.getAbsolutePath());
            engine.writeReports("SecCheck Self-Scan", outputDir, "ALL", null);

            for (Dependency dep : engine.getDependencies()) {
                int n = dep.getVulnerabilities().size();
                if (n > 0) {
                    vulnerableDeps++;
                    totalCves += n;
                    System.out.println("[SelfScan]  - " + dep.getFileName() + ": " + n + " CVE(s)");
                    for (Vulnerability v : dep.getVulnerabilities()) {
                        System.out.println("[SelfScan]      * " + v.getName() + " (" + v.getSource() + ")");
                    }
                }
            }
        } finally {
            settings.cleanup();
        }

        System.out.println("[SelfScan] -------------------------------------------");
        System.out.println("[SelfScan] Resumo: " + vulnerableDeps + " dependencia(s) vulneravel(eis), "
            + totalCves + " CVE(s) total.");
        System.out.println("[SelfScan] Relatorio HTML: " + outputDir.getAbsolutePath() + "/dependency-check-report.html");

        // Nao falha o build automaticamente. Para falhar quando houver qualquer CVE, defina:
        //   -Dselfscan.failOnAnyCve=true
        boolean failOnAny = Boolean.parseBoolean(System.getProperty("selfscan.failOnAnyCve", "false"));
        if (failOnAny && totalCves > 0) {
            System.err.println("[SelfScan] FAIL: -Dselfscan.failOnAnyCve=true e ha CVE(s) no WAR.");
            System.exit(1);
        }
    }
}
