package br.com.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3Data;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.dependencycheck.Engine;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Gera o SBOM via {@link CycloneDxBuilder} e valida o JSON contra a estrutura
 * da spec CycloneDX 1.6. Garante que os campos obrigatorios existam e que os
 * detalhes ricos (vector, cwes, advisories, KEV) cheguem ao documento.
 */
class CycloneDxBuilderIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void producesValidCycloneDx16(@TempDir Path dir) throws Exception {
        Path out = dir.resolve("sbom.json");
        try (Engine engine = TestFixtures.evidenceEngine()) {
            engine.addDependency(TestFixtures.mavenDep(
                "org.apache.logging.log4j", "log4j-core", "2.14.1",
                TestFixtures.richVuln("CVE-2021-44228", 10.0,
                    CvssV3Data.SeverityType.CRITICAL, "2.17.0", true)));

            CycloneDxBuilder.writeBom(engine, out, "test");
        }

        JsonNode bom = MAPPER.readTree(Files.readString(out));

        // Cabecalho obrigatorio da spec
        assertEquals("CycloneDX", bom.path("bomFormat").asText());
        assertEquals("1.6", bom.path("specVersion").asText());
        assertTrue(bom.path("serialNumber").asText().startsWith("urn:uuid:"));
        assertTrue(bom.has("metadata"));

        // Componente
        JsonNode comp = bom.path("components").path(0);
        assertEquals("library", comp.path("type").asText());
        assertEquals("log4j-core", comp.path("name").asText());
        assertEquals("2.14.1", comp.path("version").asText());
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", comp.path("purl").asText());

        // Vulnerabilidade (VEX-style) com detalhes ricos
        JsonNode vuln = bom.path("vulnerabilities").path(0);
        assertEquals("CVE-2021-44228", vuln.path("id").asText());
        assertEquals("NVD", vuln.path("source").path("name").asText());
        assertTrue(vuln.path("description").asText().length() > 0);

        JsonNode rating = vuln.path("ratings").path(0);
        assertEquals(10.0, rating.path("score").asDouble(), 0.001);
        assertEquals("critical", rating.path("severity").asText());
        assertEquals("CVSSv31", rating.path("method").asText());
        assertTrue(rating.path("vector").asText().startsWith("CVSS:3.1"));

        // cwes como inteiros
        JsonNode cwes = vuln.path("cwes");
        assertTrue(cwes.isArray());
        boolean has502 = false;
        for (JsonNode c : cwes) if (c.asInt() == 502) has502 = true;
        assertTrue(has502, "cwes deve conter o inteiro 502");

        // advisories e affects
        assertTrue(vuln.path("advisories").path(0).path("url").asText().contains("CVE-2021-44228"));
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            vuln.path("affects").path(0).path("ref").asText());

        // CISA KEV vira property
        JsonNode props = vuln.path("properties");
        boolean kev = false;
        for (JsonNode p : props) {
            if ("seccheck:cisa-kev".equals(p.path("name").asText())
                && "true".equals(p.path("value").asText())) kev = true;
        }
        assertTrue(kev, "CVE KEV deve virar property seccheck:cisa-kev=true");
    }

    @Test
    void emptyEngineProducesValidEmptyBom(@TempDir Path dir) throws Exception {
        Path out = dir.resolve("empty.json");
        try (Engine engine = TestFixtures.evidenceEngine()) {
            CycloneDxBuilder.writeBom(engine, out, "test");
        }
        JsonNode bom = MAPPER.readTree(Files.readString(out));
        assertEquals("CycloneDX", bom.path("bomFormat").asText());
        assertTrue(bom.path("components").isArray());
        assertEquals(0, bom.path("components").size());
        assertEquals(0, bom.path("vulnerabilities").size());
    }
}
