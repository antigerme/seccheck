package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.utils.Settings;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@WebListener
public class DatabaseUpdater implements ServletContextListener {

    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    public static final ReentrantReadWriteLock DB_LOCK = new ReentrantReadWriteLock();

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        LogUtils.info("DatabaseUpdater - contextInitialized chamado pelo container Servlet.");
        LogUtils.info("Iniciando scheduler do update da base NVD...");
        
        scheduler.scheduleAtFixedRate(() -> {
            LogUtils.info("--------------------------------------------------");
            LogUtils.info("Rotina de atualizacao do banco de dados ACIONADA.");
            updateDatabase();
            LogUtils.info("--------------------------------------------------");
        }, 10, 4 * 60, TimeUnit.MINUTES);
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        LogUtils.info("DatabaseUpdater - contextDestroyed chamado. Derrubando scheduler...");
        scheduler.shutdownNow();
    }

    private void updateDatabase() {
        LogUtils.info("updateDatabase() -> Aguardando WriteLock. Nenhuma outra thread podera fazer scan agora.");
        DB_LOCK.writeLock().lock();
        LogUtils.info("WriteLock ADQUIRIDO.");
        try {
            LogUtils.info("Criando settings para o update...");
            Settings settings = DependencyCheckRunner.createSettings();
            
            LogUtils.info("Instanciando Engine apenas para update...");
            try (Engine engine = new Engine(settings)) {
                LogUtils.info("Fazendo download/atualizacao do banco de dados (engine.doUpdates())...");
                engine.doUpdates();
                LogUtils.info("Atualizacao concluida no Engine com sucesso.");
            } catch (Exception e) {
                LogUtils.error("Falha ao executar doUpdates() no Engine", e);
            } finally {
                LogUtils.info("Limpando settings apos update.");
                settings.cleanup();
            }
        } finally {
            LogUtils.info("Liberando WriteLock.");
            DB_LOCK.writeLock().unlock();
        }
    }
}
