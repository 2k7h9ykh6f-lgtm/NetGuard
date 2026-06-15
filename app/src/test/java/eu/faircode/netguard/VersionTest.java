package eu.faircode.netguard;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link Version} — pure Java, no Android dependencies required.
 */
public class VersionTest {

    @Test
    public void equalVersions_compareEqual() {
        assertEquals(0, new Version("2.335").compareTo(new Version("2.335")));
    }

    @Test
    public void higherMajor_isGreater() {
        assertTrue(new Version("3.0").compareTo(new Version("2.335")) > 0);
    }

    @Test
    public void lowerMinor_isLess() {
        assertTrue(new Version("2.334").compareTo(new Version("2.335")) < 0);
    }

    @Test
    public void differentSegmentLength_paddedWithZero() {
        // "2.0" should equal "2.0.0"
        assertEquals(0, new Version("2.0").compareTo(new Version("2.0.0")));
    }

    @Test
    public void betaSuffix_isStripped() {
        assertEquals(0, new Version("2.335-beta").compareTo(new Version("2.335")));
    }

    @Test
    public void toString_returnsCleanVersion() {
        assertEquals("2.335", new Version("2.335-beta").toString());
    }

    @Test
    public void threeSegmentVersion_comparesCorrectly() {
        assertTrue(new Version("1.2.3").compareTo(new Version("1.2.4")) < 0);
        assertTrue(new Version("1.3.0").compareTo(new Version("1.2.9")) > 0);
    }
}
