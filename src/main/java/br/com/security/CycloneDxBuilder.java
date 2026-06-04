package br.com.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Gera um SBOM no formato CycloneDX 1.6 (JSON) a partir das dependencias
 * detectadas pelo OWASP Dependency-Check.
 *
 * Por que escrever a mao em vez de usar {@code cyclonedx-core-java}:
 * essa biblioteca arrasta varios JARs transitivos pro WAR (Jackson XML,
 * commons-collections4, etc.), e a spec do CycloneDX e estavel e simples.
 * Escrevendo via Jackson (ja presente nas deps) o WAR fica enxuto e
 * coerente com a postura dependency-conscious de um scanner de seguranca.
 *
 * Por que nao usar {@code engine.writeReports(..., "CYCLONEDX", null)}:
 * o enum {@code ReportGenerator.Format} do dep-check-core NAO tem CYCLONEDX
 * (so HTML/XML/CSV/JSON/JUNIT/SARIF/JENKINS/GITLAB/ALL). Quando a string
 * nao casa, o motor cai num fallback de "Velocity template customizado",
 * tenta carregar um template chamado "CYCLONEDX" que nao existe, e falha.
 * O plugin {@code dependency-check-maven} gera o CycloneDX por fora,
 * usando a biblioteca cyclonedx-core-java — exatamente o que evitamos
 * aqui escrevendo o JSON diretamente.
 *
 * O SBOM inclui {@code components} (uma entrada por dep Maven detectada)
 * e {@code vulnerabilities} (estilo VEX, referenciando os bom-refs dos
 * componentes afetados). Util pra pipelines de compliance que consomem
 * SBOMs CycloneDX (EO 14028 nos EUA, NIS2 na UE).
 */
public final class CycloneDxBuilder {

    private static final String SPEC_VERSION = "1.6";
    private static final ObjectMapper MAPPER = new ObjectMapper()
        .enable(SerializationFeature.INDENT_OUTPUT);

    private CycloneDxBuilder() {}

    /**
     * Escreve um SBOM CycloneDX (JSON) das dependencias detectadas pela
     * engine no arquivo informado. Retorna o caminho efetivo escrito.
     */
    public static Path writeBom(Engine engine, Path output, String appName) throws IOException {
        ObjectNode bom = MAPPER.createObjectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", SPEC_VERSION);
        bom.put("serialNumber", "urn:uuid:" + UUID.randomUUID());
        bom.put("version", 1);

        ObjectNode metadata = bom.putObject("metadata");
        metadata.put("timestamp", Instant.now().toString());
        ArrayNode toolComponents = metadata.putObject("tools").putArray("components");
        ObjectNode tool = toolComponents.addObject();
        tool.put("type", "application");
        tool.put("name", "SecCheck");
        String ver = BuildInfo.get("Implementation-Version");
        if (ver != null) tool.put("version", ver);

        // Components — uma entrada por dep Maven que tenha purl extraido.
        // Mapa de coord (group:artifact:version) -> bom-ref para referenciar
        // nas vulnerabilities sem duplicar.
        ArrayNode components = bom.putArray("components");
        Map<String, String> bomRefByCoord = new HashMap<>();

        for (Dependency dep : engine.getDependencies()) {
            FixSuggester.MavenCoord coord = FixSuggester.extractMavenCoord(dep);
            if (coord == null) continue;
            String key = coord.groupId() + ":" + coord.artifactId() + ":" + coord.version();
            if (bomRefByCoord.containsKey(key)) continue; // dedupe
            String bomRef = "pkg:maven/" + coord.groupId() + "/" + coord.artifactId()
                + "@" + coord.version();
            bomRefByCoord.put(key, bomRef);

            ObjectNode c = components.addObject();
            c.put("type", "library");
            c.put("bom-ref", bomRef);
            c.put("group", coord.groupId());
            c.put("name", coord.artifactId());
            c.put("version", coord.version());
            c.put("purl", bomRef);
        }

        // Vulnerabilities — VEX-style, com referencia aos bom-refs afetados.
        ArrayNode vulns = bom.putArray("vulnerabilities");
        for (Dependency dep : engine.getDependencies()) {
            if (dep.getVulnerabilities().isEmpty()) continue;
            FixSuggester.MavenCoord coord = FixSuggester.extractMavenCoord(dep);
            if (coord == null) continue;
            String affectedRef = bomRefByCoord.get(
                coord.groupId() + ":" + coord.artifactId() + ":" + coord.version());
            if (affectedRef == null) continue;

            for (Vulnerability v : dep.getVulnerabilities()) {
                String cveId = safeName(v);
                if (cveId == null || cveId.isBlank()) continue;
                ObjectNode vuln = vulns.addObject();
                vuln.put("bom-ref", "vuln-" + cveId + "-" + affectedRef.hashCode());
                vuln.put("id", cveId);
                String source = safeSource(v);
                if (source != null) vuln.putObject("source").put("name", source);

                double score = Severity.extractBaseScore(v);
                if (score > 0) {
                    ObjectNode rating = vuln.putArray("ratings").addObject();
                    rating.put("score", score);
                    rating.put("method", "CVSSv3");
                    rating.put("severity", Severity.Level.ofCvss(score).name().toLowerCase(Locale.ROOT));
                }
                vuln.putArray("affects").addObject().put("ref", affectedRef);
            }
        }

        Files.createDirectories(output.getParent());
        try (var writer = Files.newBufferedWriter(output)) {
            MAPPER.writeValue(writer, bom);
        }
        return output;
    }

    private static String safeName(Vulnerability v) {
        try {
            Object res = v.getClass().getMethod("getName").invoke(v);
            return res == null ? null : res.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String safeSource(Vulnerability v) {
        try {
            Object src = v.getClass().getMethod("getSource").invoke(v);
            if (src == null) return null;
            // Source pode ser enum ou string; toString() basta para o JSON
            String s = src.toString();
            return s.isBlank() ? null : s;
        } catch (Exception e) {
            return null;
        }
    }
}
