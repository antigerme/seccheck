package br.com.security;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Ciclo de vida unico da aplicacao:
 *
 * <ul>
 *   <li>Cria o pool de threads compartilhado para scans (substitui o pool
 *       privado que vivia no UploadServlet)</li>
 *   <li>Liga o cleaner do {@link ScanManager}</li>
 *   <li>Dispara um bootstrap inicial assincrono do banco NVD (evita que o
 *       primeiro scan falhe quando DPCK_DATA_DIR esta vazio)</li>
 *   <li>Encerra tudo ordenadamente em contextDestroyed, com awaitTermination
 *       para evitar varreduras orfas durante undeploy</li>
 * </ul>
 *
 * O tamanho do pool e configuravel via {@code DPCK_THREAD_POOL_SIZE} (padrao 2).
 * Tamanhos &gt; 1 aceleram a fila mas concorrem pelo mesmo banco H2 em
 * {@code DPCK_DATA_DIR}; em ambientes com I/O lento, mantenha em 1.
 */
@WebListener
public class AppContextListener implements ServletContextListener {

    private static volatile ExecutorService scanExecutor;
    // Pool separado e pequeno para as chamadas a Claude API (resumo executivo).
    // Mantido fora do scanExecutor porque e I/O-bound (rede) e nao deve competir
    // com os scans, que sao CPU/memoria-bound.
    private static volatile ExecutorService summaryExecutor;
    private static volatile int poolSize;
    private static volatile int queueCapacity;

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        BuildInfo.load(sce.getServletContext());

        poolSize = getEnvInt("DPCK_THREAD_POOL_SIZE", 2);
        queueCapacity = getEnvInt("DPCK_QUEUE_CAPACITY", 10);

        AtomicInteger threadCounter = new AtomicInteger();
        scanExecutor = Executors.newFixedThreadPool(poolSize, r -> {
            Thread t = new Thread(r, "dpck-scan-" + threadCounter.incrementAndGet());
            t.setDaemon(false);
            return t;
        });
        LogUtils.info("AppContextListener: pool de scans criado (" + poolSize + " threads, " +
            "capacidade da fila: " + queueCapacity + ")");

        AtomicInteger summaryCounter = new AtomicInteger();
        summaryExecutor = Executors.newFixedThreadPool(getEnvInt("DPCK_SUMMARY_POOL_SIZE", 2), r -> {
            Thread t = new Thread(r, "dpck-summary-" + summaryCounter.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
        if (ExecutiveSummaryService.isEnabled()) {
            LogUtils.info("AppContextListener: resumo executivo ATIVADO (modelo: " +
                ExecutiveSummaryService.model() + ").");
        } else {
            LogUtils.info("AppContextListener: resumo executivo desativado (ANTHROPIC_API_KEY ausente).");
        }

        ScanManager.startCleaner();
        DatabaseUpdater.start();
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        LogUtils.info("AppContextListener: derrubando aplicacao...");

        DatabaseUpdater.shutdown();
        ScanManager.shutdown();

        if (scanExecutor != null) {
            scanExecutor.shutdown();
            try {
                if (!scanExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
                    LogUtils.warn("Pool de scans nao terminou em 60s. Forcando shutdownNow().");
                    scanExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                scanExecutor.shutdownNow();
            }
        }
        if (summaryExecutor != null) {
            summaryExecutor.shutdownNow();
        }
        LogUtils.info("AppContextListener: aplicacao encerrada.");
    }

    public static ExecutorService scanExecutor() {
        return scanExecutor;
    }

    public static ExecutorService summaryExecutor() {
        return summaryExecutor;
    }

    public static int queueSize() {
        if (scanExecutor instanceof ThreadPoolExecutor tpe) {
            return tpe.getQueue().size();
        }
        return 0;
    }

    public static int poolSize() {
        return poolSize;
    }

    public static int queueCapacity() {
        return queueCapacity;
    }

    public static boolean isQueueFull() {
        return queueSize() >= queueCapacity;
    }

    /** Padroniza leitura de inteiros de ambiente. */
    public static int getEnvInt(String name, int defaultValue) {
        String val = System.getenv(name);
        if (val == null || val.isBlank()) return defaultValue;
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            LogUtils.warn("Variavel " + name + " com valor invalido (" + val + "). Usando padrao " + defaultValue);
            return defaultValue;
        }
    }

    /** Padroniza leitura de longs de ambiente. */
    public static long getEnvLong(String name, long defaultValue) {
        String val = System.getenv(name);
        if (val == null || val.isBlank()) return defaultValue;
        try {
            return Long.parseLong(val.trim());
        } catch (NumberFormatException e) {
            LogUtils.warn("Variavel " + name + " com valor invalido (" + val + "). Usando padrao " + defaultValue);
            return defaultValue;
        }
    }
}
