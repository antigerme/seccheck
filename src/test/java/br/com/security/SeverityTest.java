package br.com.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Limites da escala CVSS v3 (NONE/LOW/MEDIUM/HIGH/CRITICAL). */
class SeverityTest {

    @Test
    void boundariesMapToCorrectLevels() {
        assertEquals(Severity.Level.NONE, Severity.Level.ofCvss(0.0));
        assertEquals(Severity.Level.LOW, Severity.Level.ofCvss(0.1));
        assertEquals(Severity.Level.LOW, Severity.Level.ofCvss(3.9));
        assertEquals(Severity.Level.MEDIUM, Severity.Level.ofCvss(4.0));
        assertEquals(Severity.Level.MEDIUM, Severity.Level.ofCvss(6.9));
        assertEquals(Severity.Level.HIGH, Severity.Level.ofCvss(7.0));
        assertEquals(Severity.Level.HIGH, Severity.Level.ofCvss(8.9));
        assertEquals(Severity.Level.CRITICAL, Severity.Level.ofCvss(9.0));
        assertEquals(Severity.Level.CRITICAL, Severity.Level.ofCvss(10.0));
    }

    @Test
    void negativeOrZeroIsNone() {
        assertEquals(Severity.Level.NONE, Severity.Level.ofCvss(0.0));
        assertEquals(Severity.Level.NONE, Severity.Level.ofCvss(-1.0));
    }

    @Test
    void ordinalOrderingReflectsRisk() {
        // worstOf() e a UI dependem dessa ordem para comparar severidades.
        assertEquals(true, Severity.Level.CRITICAL.ordinal() > Severity.Level.HIGH.ordinal());
        assertEquals(true, Severity.Level.HIGH.ordinal() > Severity.Level.MEDIUM.ordinal());
        assertEquals(true, Severity.Level.MEDIUM.ordinal() > Severity.Level.LOW.ordinal());
        assertEquals(true, Severity.Level.LOW.ordinal() > Severity.Level.NONE.ordinal());
    }
}
