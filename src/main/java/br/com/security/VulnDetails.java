package br.com.security;

import org.owasp.dependencycheck.dependency.Vulnerability;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Extracao centralizada e tolerante a versao dos detalhes de uma
 * {@link Vulnerability} do dependency-check. E a UNICA fonte de reflection
 * sobre o objeto Vulnerability no projeto — tanto o {@link CycloneDxBuilder}
 * (SBOM) quanto o {@link FindingsExtractor} (API /api/status) consomem isto,
 * garantindo paridade de dados entre o SBOM e a API REST.
 *
 * Toda extracao e via reflection: se a API do dep-check mudar entre versoes,
 * o campo afetado vira null/vazio em vez de quebrar a geracao inteira.
 */
public final class VulnDetails {

    /** Referencia/advisory de uma CVE (URL + titulo opcional). */
    public record Advisory(String title, String url) {}

    public final String cveName;
    public final String source;        // NVD, OSSINDEX, etc.
    public final String description;
    public final double cvssScore;     // 0 se desconhecido
    public final String cvssVector;    // ex.: "CVSS:3.1/AV:N/..." ou null
    public final Severity.Level severity;
    public final List<Integer> cwes;   // ex.: [502, 917]
    public final List<Advisory> advisories;
    public final boolean knownExploited; // CISA KEV

    private VulnDetails(String cveName, String source, String description, double cvssScore,
                        String cvssVector, Severity.Level severity, List<Integer> cwes,
                        List<Advisory> advisories, boolean knownExploited) {
        this.cveName = cveName;
        this.source = source;
        this.description = description;
        this.cvssScore = cvssScore;
        this.cvssVector = cvssVector;
        this.severity = severity;
        this.cwes = cwes;
        this.advisories = advisories;
        this.knownExploited = knownExploited;
    }

    /**
     * Extrai todos os detalhes de uma Vulnerability. Retorna null se a CVE
     * nao tiver nome (sem nome nao da pra referenciar/diff).
     */
    public static VulnDetails from(Vulnerability v) {
        String name = invokeString(v, "getName");
        if (name == null || name.isBlank()) return null;

        double score = Severity.extractBaseScore(v);
        return new VulnDetails(
            name.trim(),
            extractSource(v),
            trimToNull(invokeString(v, "getDescription")),
            score,
            extractCvssVector(v),
            Severity.Level.ofCvss(score),
            extractCwes(v),
            extractAdvisories(v),
            isKnownExploited(v));
    }

    /** Detecta a versao do metodo CVSS pelo prefixo do vector (default CVSSv3). */
    public String cvssMethod() {
        if (cvssVector != null && cvssVector.startsWith("CVSS:3.1")) return "CVSSv31";
        if (cvssVector != null && cvssVector.startsWith("CVSS:4")) return "CVSSv4";
        return "CVSSv3";
    }

    // ===== helpers de reflection (tolerantes) =====

    private static String invokeString(Object target, String method) {
        try {
            Object res = target.getClass().getMethod(method).invoke(target);
            return res == null ? null : res.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String extractSource(Vulnerability v) {
        String s = invokeString(v, "getSource");
        return (s == null || s.isBlank()) ? null : s;
    }

    /** v.getCvssV3().getCvssData().getVectorString() — tolera ausencia de v3. */
    private static String extractCvssVector(Vulnerability v) {
        try {
            Object cvss = v.getClass().getMethod("getCvssV3").invoke(v);
            if (cvss == null) return null;
            Object data = cvss.getClass().getMethod("getCvssData").invoke(cvss);
            if (data == null) return null;
            Object vec = data.getClass().getMethod("getVectorString").invoke(data);
            return vec == null ? null : vec.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** CweSet.getEntries() devolve Set de "CWE-79" -> List<Integer> [79]. */
    private static List<Integer> extractCwes(Vulnerability v) {
        List<Integer> out = new ArrayList<>();
        try {
            Object cweSet = v.getClass().getMethod("getCwes").invoke(v);
            if (cweSet == null) return out;
            Object entries = cweSet.getClass().getMethod("getEntries").invoke(cweSet);
            if (entries instanceof Collection<?> coll) {
                for (Object e : coll) {
                    if (e == null) continue;
                    Integer num = parseCweNumber(e.toString());
                    if (num != null) out.add(num);
                }
            }
        } catch (Exception ignored) {}
        return out;
    }

    /** "CWE-79" / "cwe-79" / "79" -> 79. null se nao houver digitos. */
    private static Integer parseCweNumber(String cwe) {
        if (cwe == null) return null;
        String digits = cwe.replaceAll("[^0-9]", "");
        if (digits.isBlank()) return null;
        try {
            return Integer.valueOf(digits);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Reference -> Advisory {title, url}, deduplicado por URL. */
    private static List<Advisory> extractAdvisories(Vulnerability v) {
        List<Advisory> out = new ArrayList<>();
        try {
            Object refs = v.getClass().getMethod("getReferences").invoke(v);
            if (refs instanceof Collection<?> coll) {
                Set<String> seen = new HashSet<>();
                for (Object r : coll) {
                    if (r == null) continue;
                    String url = invokeString(r, "getUrl");
                    if (url == null || url.isBlank() || !seen.add(url)) continue;
                    out.add(new Advisory(trimToNull(invokeString(r, "getName")), url.trim()));
                }
            }
        } catch (Exception ignored) {}
        return out;
    }

    private static boolean isKnownExploited(Vulnerability v) {
        try {
            return v.getClass().getMethod("getKnownExploitedVulnerability").invoke(v) != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
