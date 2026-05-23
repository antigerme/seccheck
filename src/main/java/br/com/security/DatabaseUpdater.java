package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.utils.Settings;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Mantem o banco NVD atualizado em segundo plano.
 *
 * Mudancas em relacao a versao anterior:
 * <ul>
 *   <li>Bootstrap eager: se {@code DPCK_DATA_DIR} estiver vazio na inicializacao,
 *       rodamos um update imediato (em thread separada para nao travar o boot)
 *       antes do agendamento periodico. Sem isso o primeiro scan falha.</li>
 *   <li>Tornou-se uma classe utilitaria estatica controlada pelo
 *       {@link AppContextListener}, removendo a anotacao {@code @WebListener}
 *       duplicada.</li>
 *   <li>Intervalo configuravel via {@code DPCK_UPDATE_INTERVAL_HOURS}
 *       (padrao 4h).</li>
 * </ul>
 */
public final class DatabaseUpdater {

    public static final ReentrantReadWriteLock DB_LOCK = new ReentrantReadWriteLock();

    private static volatile ScheduledExecutorService scheduler;

    private DatabaseUpdater() {}

    public static synchronized void start() {
        if (scheduler != null) return;

        long intervalHours = AppContextListener.getEnvLong("DPCK_UPDATE_INTERVAL_HOURS", 4);
        long intervalMinutes = intervalHours * 60;

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "dpck-nvd-updater");
            t.setDaemon(true);
            return t;
        });

        if (needsBootstrap()) {
            LogUtils.info("Bootstrap: banco NVD vazio. Disparando update imediato em background.");
            scheduler.submit(DatabaseUpdater::updateDatabase);
        } else {
            LogUtils.info("Bootstrap: banco NVD ja existe em " + resolveDataDir() + ". Pulando update inicial.");
        }

        scheduler.scheduleAtFixedRate(() -> {
            LogUtils.info("Rotina periodica do banco NVD acionada.");
            updateDatabase();
        }, intervalMinutes, intervalMinutes, TimeUnit.MINUTES);

        LogUtils.info("DatabaseUpdater iniciado (intervalo: " + intervalHours + "h)");
    }

    public static synchronized void shutdown() {
        if (scheduler == null) return;
        scheduler.shutdownNow();
        try {
            if (!scheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                LogUtils.warn("Scheduler do NVD nao parou em 30s.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        scheduler = null;
    }

    private static boolean needsBootstrap() {
        File dir = new File(resolveDataDir());
        if (!dir.exists()) return true;
        File[] entries = dir.listFiles();
        return entries == null || entries.length == 0;
    }

    private static String resolveDataDir() {
        String dataDir = System.getenv("DPCK_DATA_DIR");
        if (dataDir == null || dataDir.isBlank()) {
            dataDir = System.getProperty("user.home") + "/.dependency-check/data";
        }
        return dataDir;
    }

    static void updateDatabase() {
        LogUtils.info("updateDatabase() -> aguardando WriteLock (scans em andamento pausarao).");
        DB_LOCK.writeLock().lock();
        LogUtils.info("WriteLock adquirido.");
        long start = System.currentTimeMillis();
        try {
            // Garante que o diretorio existe (criar antes que o motor reclame)
            try {
                Files.createDirectories(Path.of(resolveDataDir()));
            } catch (Exception ignored) {
                // Vai falhar dentro do Engine com mensagem mais clara, se for o caso
            }

            Settings settings = DependencyCheckRunner.createSettings();
            try (Engine engine = new Engine(settings)) {
                LogUtils.info("Engine.doUpdates() iniciando...");
                engine.doUpdates();
                long elapsed = System.currentTimeMillis() - start;
                LogUtils.info("Atualizacao NVD concluida em " + elapsed + "ms.");
                Metrics.nvdUpdatesOk.incrementAndGet();
                Metrics.lastNvdUpdateMs.set(System.currentTimeMillis());
            } catch (Exception e) {
                LogUtils.error("Falha ao executar doUpdates() no Engine", e);
                Metrics.nvdUpdatesFailed.incrementAndGet();
            } finally {
                settings.cleanup();
            }
        } finally {
            DB_LOCK.writeLock().unlock();
            LogUtils.info("WriteLock liberado.");
        }
    }
}
