package br.com.security;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import java.util.ArrayList;
import java.util.List;

/**
 * Extrai a lista plana de {@link ScanFinding}s a partir das vulnerabilidades
 * reportadas pela Engine. Alimenta o Diff Scan e a API /api/status.
 *
 * A extracao de cada vulnerabilidade e delegada a {@link VulnDetails}, a mesma
 * usada pelo {@link CycloneDxBuilder} — garante que a API e o SBOM exponham
 * exatamente os mesmos dados.
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
                VulnDetails details = VulnDetails.from(v);
                if (details == null) continue; // CVE sem nome — ignora
                out.add(new ScanFinding(
                    coord.groupId(), coord.artifactId(), coord.version(), details));
            }
        }
        return out;
    }
}
