package br.com.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Facade para SLF4J. Mantemos a API existente (debug/info/error) para nao
 * espalhar refatoracoes pelos chamadores, mas internamente delegamos para o
 * SLF4J — o mesmo logger que o motor do dependency-check usa. Isso garante
 * formato e nivel de log consistentes em toda a aplicacao.
 *
 * O nivel continua sendo configurado pela variavel de ambiente DPCK_DEBUG
 * (trace/debug/info/warn/error/off) e propagado para o SLF4J Simple Logger.
 */
public class LogUtils {

    private static final Logger LOG = LoggerFactory.getLogger("br.com.security");

    public static final String LOG_LEVEL = getEnvLogLevel();
    public static final boolean DEBUG = isDebugOrTrace();

    private static String getEnvLogLevel() {
        String envLevel = System.getenv("DPCK_DEBUG");
        if (envLevel == null || envLevel.isBlank()) {
            return "info";
        }
        String level = envLevel.trim().toLowerCase();
        if ("true".equals(level)) return "debug";
        if ("false".equals(level)) return "info";
        return level;
    }

    private static boolean isDebugOrTrace() {
        return "debug".equals(LOG_LEVEL) || "trace".equals(LOG_LEVEL);
    }

    static {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", LOG_LEVEL);
        System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
        System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "yyyy-MM-dd HH:mm:ss.SSS");
        System.setProperty("org.slf4j.simpleLogger.showThreadName", "true");
        System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
    }

    public static void debug(String msg) {
        LOG.debug(msg);
    }

    public static void info(String msg) {
        LOG.info(msg);
    }

    public static void warn(String msg) {
        LOG.warn(msg);
    }

    public static void error(String msg, Throwable t) {
        if (t == null) {
            LOG.error(msg);
        } else if (DEBUG) {
            LOG.error(msg, t);
        } else {
            LOG.error("{} (motivo: {})", msg, t.toString());
        }
    }
}
