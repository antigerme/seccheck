package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import java.util.ArrayList;
import java.util.List;

/**
 * Extrai a lista plana de {@link ScanFinding}s a partir das vulnerabilidades
 * reportadas pela Engine. Usado pela feature de Diff Scan — o cliente recebe
 * essa lista por scan e computa delta entre dois scans (mesma
 * {@code group:artifact:cveName} = mesma finding).
 */
public final class FindingsExtractor {

    private FindingsExtractor() {}

    public static List<ScanFinding> extract(Engine engine) {
        List<ScanFinding> out = new ArrayList<>();
        for (Dependency dep : engine.getDependencies()) {
            if (dep.getVulnerabilities().isEmpty()) continue;
            FixSuggester.MavenCoord coord = FixSuggester.extractMavenCoord(dep);
            if (coord == null) continue;
            for (Vulnerability v : dep.getVulnerabilities()) {
                String name = safeName(v);
                if (name == null || name.isBlank()) continue;
                double score = Severity.extractBaseScore(v);
                Severity.Level lvl = Severity.Level.ofCvss(score);
                out.add(new ScanFinding(
                    coord.groupId(), coord.artifactId(), coord.version(),
                    name, lvl, score));
            }
        }
        return out;
    }

    private static String safeName(Vulnerability v) {
        try {
            Object res = v.getClass().getMethod("getName").invoke(v);
            return res == null ? null : res.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
