package br.com.security;

public class LogUtils {
    // Variavel DPCK_DEBUG agora aceita niveis do Java/SLF4J (trace, debug, info, warn, error, off)
    public static final String LOG_LEVEL = getEnvLogLevel();
    public static final boolean DEBUG = isDebugOrTrace();

    private static String getEnvLogLevel() {
        String envLevel = System.getenv("DPCK_DEBUG");
        if (envLevel == null || envLevel.isBlank()) {
            return "info"; // Padrao caso a variavel nao seja definida
        }
        String level = envLevel.trim().toLowerCase();
        
        // Fallback de compatibilidade para caso alguem ainda passe "true" ou "false"
        if ("true".equals(level)) return "debug";
        if ("false".equals(level)) return "info";
        
        return level;
    }

    private static boolean isDebugOrTrace() {
        return "debug".equals(LOG_LEVEL) || "trace".equals(LOG_LEVEL);
    }

    static {
        // Aplica o nivel de log escolhido pelo usuario direto no motor do OWASP (SLF4J Simple Logger)
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", LOG_LEVEL);
        
        if (DEBUG) {
            System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
            System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss");
        }
    }

    public static void debug(String msg) {
        if (DEBUG) {
            System.out.println("[DPCK " + LOG_LEVEL.toUpperCase() + "] " + msg);
        }
    }
    
    public static void info(String msg) {
        // INFO exibe apenas se o nivel for info, debug ou trace
        if ("info".equals(LOG_LEVEL) || DEBUG) {
            System.out.println("[DPCK INFO] " + msg);
        }
    }
    
    public static void error(String msg, Throwable t) {
        // ERROR exibe sempre, a menos que o log esteja desligado (off)
        if (!"off".equals(LOG_LEVEL)) {
            System.err.println("[DPCK ERROR] " + msg);
            if (t != null) {
                // Se estiver em debug, mostra a arvore inteira da excecao (StackTrace)
                // Caso contrario, mostra apenas a mensagem principal do erro pra nao poluir o log.
                if (DEBUG) {
                    t.printStackTrace();
                } else {
                    System.err.println("Motivo: " + t.toString());
                }
            }
        }
    }
}
