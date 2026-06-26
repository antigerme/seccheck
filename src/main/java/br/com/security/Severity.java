package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

/**
 * Classifica a "pior" severidade encontrada em um scan, baseado no CVSS
 * base score das vulnerabilidades reportadas. Usado pela UI (mood blobs)
 * pra refletir visualmente o estado de risco.
 *
 * A extracao do score usa reflection para tolerar mudancas de API entre
 * versoes do dependency-check-core (ex.: 12.x vs futuro 13.x). Se nada
 * casar, a severidade fica NONE — a UI cai no comportamento default.
 */
public final class Severity {

    public enum Level {
        NONE, LOW, MEDIUM, HIGH, CRITICAL;

        /** Escala CVSS v3 padrao do NVD. */
        public static Level ofCvss(double score) {
            if (score >= 9.0) return CRITICAL;
            if (score >= 7.0) return HIGH;
            if (score >= 4.0) return MEDIUM;
            if (score >= 0.1) return LOW;
            return NONE;
        }
    }

    private Severity() {}

    /** Walks all dependencies + vulnerabilidades e retorna o nivel mais grave. */
    public static Level worstOf(Engine engine) {
        Level worst = Level.NONE;
        for (Dependency dep : engine.getDependencies()) {
            for (Vulnerability v : dep.getVulnerabilities()) {
                double score = extractBaseScore(v);
                Level lvl = Level.ofCvss(score);
                if (lvl.ordinal() > worst.ordinal()) {
                    worst = lvl;
                    if (worst == Level.CRITICAL) return worst; // ja achou o pior, encurta
                }
            }
        }
        return worst;
    }

    /**
     * Extrai o maior CVSS base score (v4 > v3 > v2 quando presentes).
     * Tolerante a duas variantes de API:
     *   1) {@code v.getCvssV{X}().getCvssData().getBaseScore()} (12.x+)
     *   2) {@code v.getCvssV{X}().getBaseScore()} (versoes mais antigas)
     *
     * Preferencia pelo mais novo: CVEs publicados a partir de 2024 vem com
     * CVSSv4 e frequentemente SEM v3/v2. Se nao tentassemos v4 primeiro, esses
     * CVEs ficariam com score 0 e severidade NONE — e a UI mostraria o cofre
     * "limpo" mesmo com vulnerabilidade real (era o bug pre-fix).
     */
    static double extractBaseScore(Vulnerability v) {
        double v4 = tryExtract(v, "getCvssV4");
        if (v4 > 0) return v4;
        double v3 = tryExtract(v, "getCvssV3");
        if (v3 > 0) return v3;
        return tryExtract(v, "getCvssV2");
    }

    private static double tryExtract(Object vuln, String accessor) {
        try {
            Object cvss = vuln.getClass().getMethod(accessor).invoke(vuln);
            if (cvss == null) return 0;
            // Variante moderna: cvss.getCvssData().getBaseScore()
            try {
                Object data = cvss.getClass().getMethod("getCvssData").invoke(cvss);
                if (data != null) {
                    return toDouble(data.getClass().getMethod("getBaseScore").invoke(data));
                }
            } catch (NoSuchMethodException ignored) {
                // cai pra variante direta
            }
            // Variante antiga: cvss.getBaseScore()
            return toDouble(cvss.getClass().getMethod("getBaseScore").invoke(cvss));
        } catch (Exception ignored) {
            return 0;
        }
    }

    private static double toDouble(Object o) {
        if (o instanceof Number n) return n.doubleValue();
        if (o == null) return 0;
        try {
            return Double.parseDouble(o.toString());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
