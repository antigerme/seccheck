package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Gera {@link FixSuggestion}s a partir das vulnerabilidades reportadas pela
 * Engine. Estrategia:
 *
 * <ol>
 *   <li>Identifica deps Maven via Package URL (purl) extraido dos identifiers
 *       de cada {@link Dependency}.</li>
 *   <li>Agrupa por {@code group:artifact} (multiplas CVEs num mesmo artefato
 *       viram um snippet so com a maior versao de fix).</li>
 *   <li>Extrai a versao "fixed in" via {@code versionEndExcluding} das
 *       matches do CVE — usa reflection para tolerar mudancas de API entre
 *       versoes do dependency-check-core.</li>
 *   <li>Se nao conseguir determinar a versao de fix, omite o snippet (o
 *       relatorio HTML ainda mostra a CVE; o usuario decide manualmente).</li>
 * </ol>
 */
public final class FixSuggester {

    // pkg:maven/<group>/<artifact>@<version>  (espec do Package URL para Maven)
    private static final Pattern PURL_MAVEN = Pattern.compile("pkg:maven/([^/]+)/([^@]+)@(.+)");

    private FixSuggester() {}

    public static List<FixSuggestion> suggest(Engine engine) {
        Map<String, Aggregate> byCoord = new LinkedHashMap<>();

        for (Dependency dep : engine.getDependencies()) {
            if (dep.getVulnerabilities().isEmpty()) continue;

            MavenCoord coord = extractMavenCoord(dep);
            if (coord == null) continue;

            String key = coord.groupId + ":" + coord.artifactId;
            Aggregate agg = byCoord.computeIfAbsent(key, k -> new Aggregate(coord));

            for (Vulnerability v : dep.getVulnerabilities()) {
                String ve = extractVersionEndExcluding(v);
                if (ve != null && compareVersions(ve, agg.fixedVersion) > 0) {
                    agg.fixedVersion = ve;
                }
                // Detalhes via VulnDetails (mesma fonte do SBOM e da API findings[]).
                VulnDetails details = VulnDetails.from(v);
                if (details == null) continue;
                agg.cves.add(details.cveName);
                if (details.severity.ordinal() > agg.worstSeverity.ordinal()) {
                    agg.worstSeverity = details.severity;
                }
                // CISA KEV: OR-acumulado — true se qualquer CVE deste artefato esta na lista.
                if (details.knownExploited) agg.knownExploited = true;
            }
        }

        List<FixSuggestion> out = new ArrayList<>();
        for (Aggregate agg : byCoord.values()) {
            if (agg.fixedVersion == null || agg.cves.isEmpty()) continue;
            out.add(new FixSuggestion(
                agg.coord.groupId,
                agg.coord.artifactId,
                agg.coord.version,
                agg.fixedVersion,
                new ArrayList<>(agg.cves),
                agg.worstSeverity,
                agg.knownExploited));
        }
        return out;
    }

    /** Package-private para reuso em {@link FindingsExtractor}. */
    record MavenCoord(String groupId, String artifactId, String version) {}

    private static final class Aggregate {
        final MavenCoord coord;
        String fixedVersion;
        final TreeSet<String> cves = new TreeSet<>();
        Severity.Level worstSeverity = Severity.Level.NONE;
        boolean knownExploited;

        Aggregate(MavenCoord coord) { this.coord = coord; }
    }

    static MavenCoord extractMavenCoord(Dependency dep) {
        // dep.getSoftwareIdentifiers() retorna Set<Identifier>; Identifier.getValue()
        // devolve o purl em forma canonica (estavel entre versoes do dep-check).
        try {
            Object idsObj = dep.getClass().getMethod("getSoftwareIdentifiers").invoke(dep);
            if (idsObj instanceof Collection<?> ids) {
                for (Object id : ids) {
                    String value = invokeString(id, "getValue");
                    if (value == null) continue;
                    Matcher m = PURL_MAVEN.matcher(value);
                    if (m.matches()) {
                        return new MavenCoord(m.group(1), m.group(2), m.group(3));
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Extrai a versao "fixed in" do CVE. Tenta primeiro o
     * {@code getMatchedVulnerableSoftware()} (singular — o match exato que
     * a engine usou); se vazio, percorre {@code getVulnerableSoftware()}
     * (Set de todas as ranges conhecidas) procurando o maior
     * {@code versionEndExcluding}.
     *
     * Bug historico: a implementacao anterior assumia que getMatched...
     * devolvia Collection, mas e singular — resultado: 0 sugestoes de fix
     * pra QUALQUER scan desde o PR #7. Corrigido aqui.
     */
    private static String extractVersionEndExcluding(Vulnerability v) {
        try {
            // 1) Match singular (mais preciso quando presente)
            Object matched = v.getClass().getMethod("getMatchedVulnerableSoftware").invoke(v);
            if (matched != null) {
                String ve = invokeString(matched, "getVersionEndExcluding");
                if (ve != null && !ve.isBlank()) return ve;
            }
            // 2) Fallback: percorre todas as VulnerableSoftware do CVE
            Object all = v.getClass().getMethod("getVulnerableSoftware").invoke(v);
            if (all instanceof Collection<?> coll) {
                String best = null;
                for (Object vs : coll) {
                    String ve = invokeString(vs, "getVersionEndExcluding");
                    if (ve != null && compareVersions(ve, best) > 0) best = ve;
                }
                return best;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String invokeString(Object target, String method) {
        try {
            Object res = target.getClass().getMethod(method).invoke(target);
            return res == null ? null : res.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Compara versoes do estilo X.Y.Z (split por dots; partes nao numericas
     * fallback a 0). Suficiente pra ordenacao de versionEndExcluding na
     * pratica, embora nao seja completamente semver-aware.
     */
    static int compareVersions(String a, String b) {
        if (a == null && b == null) return 0;
        if (a == null) return -1;
        if (b == null) return 1;
        String[] aParts = a.split("[.-]");
        String[] bParts = b.split("[.-]");
        int len = Math.max(aParts.length, bParts.length);
        for (int i = 0; i < len; i++) {
            int aN = i < aParts.length ? parseIntSafe(aParts[i]) : 0;
            int bN = i < bParts.length ? parseIntSafe(bParts[i]) : 0;
            if (aN != bN) return Integer.compare(aN, bN);
        }
        return 0;
    }

    private static int parseIntSafe(String s) {
        try { return Integer.parseInt(s.replaceAll("[^0-9].*", "")); }
        catch (NumberFormatException e) { return 0; }
    }
}
