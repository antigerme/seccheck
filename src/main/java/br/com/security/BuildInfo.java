package br.com.security;

import jakarta.servlet.ServletContext;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * Le metadados do build a partir do MANIFEST.MF do WAR (escritos pelo
 * maven-war-plugin + git-commit-id-plugin). Permite confirmar em producao
 * exatamente qual commit/build esta deployado, sem abrir o WAR.
 *
 * Carregado uma vez no startup pelo {@link AppContextListener} e exposto via
 * {@link VersionServlet} e por {@code HealthServlet}.
 */
public final class BuildInfo {

    private static volatile Map<String, String> attributes = Map.of();
    private static volatile boolean loaded = false;

    private BuildInfo() {}

    public static synchronized void load(ServletContext ctx) {
        if (loaded) return;
        Map<String, String> read = new LinkedHashMap<>();
        try (InputStream is = ctx.getResourceAsStream("/META-INF/MANIFEST.MF")) {
            if (is != null) {
                Manifest mf = new Manifest(is);
                Attributes main = mf.getMainAttributes();
                putIfPresent(read, main, "Implementation-Title");
                putIfPresent(read, main, "Implementation-Version");
                putIfPresent(read, main, "Build-Time");
                putIfPresent(read, main, "Build-Jdk");
                putIfPresent(read, main, "Git-Commit");
                putIfPresent(read, main, "Git-Commit-Short");
                putIfPresent(read, main, "Git-Commit-Time");
                putIfPresent(read, main, "Git-Branch");
                putIfPresent(read, main, "Git-Dirty");
            } else {
                LogUtils.warn("MANIFEST.MF nao encontrado em /META-INF/MANIFEST.MF");
            }
        } catch (Exception e) {
            LogUtils.error("Falha ao ler MANIFEST.MF", e);
        }
        attributes = Map.copyOf(read);
        loaded = true;

        LogUtils.info("Build deployado: " + summary());
    }

    private static void putIfPresent(Map<String, String> dest, Attributes attrs, String key) {
        String val = attrs.getValue(key);
        // git-commit-id-plugin deixa as propriedades como literal "${git.commit.id}" quando
        // o .git nao foi encontrado e a expressao Maven nao resolveu. Filtramos esse caso.
        if (val == null || val.isBlank() || val.startsWith("${")) return;
        dest.put(key, val);
    }

    public static Map<String, String> attributes() {
        return attributes;
    }

    public static String get(String key) {
        return attributes.get(key);
    }

    /** Versao + commit curto, util para logs e responses compactas. */
    public static String summary() {
        String version = attributes.getOrDefault("Implementation-Version", "unknown");
        String commit = attributes.get("Git-Commit-Short");
        String dirty = attributes.get("Git-Dirty");
        StringBuilder sb = new StringBuilder(version);
        if (commit != null) {
            sb.append(" @").append(commit);
            if ("true".equalsIgnoreCase(dirty)) sb.append("-dirty");
        }
        String buildTime = attributes.get("Build-Time");
        if (buildTime != null) sb.append(" (built ").append(buildTime).append(")");
        return sb.toString();
    }
}
