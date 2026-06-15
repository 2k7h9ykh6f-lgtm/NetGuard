package eu.faircode.netguard;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

// Util.getProtocolName is pure logic. NOTE: Util.java pulls in Android imports,
// so this class runs under the Gradle unit-test task (returnDefaultValues), not
// under the standalone javac harness used for the Android-free classes.
public class UtilProtocolNameTest {

    @Test
    public void fullNamesForKnownProtocols() {
        assertEquals("ICMP4", Util.getProtocolName(1, 4, false));
        assertEquals("ICMP6", Util.getProtocolName(58, 6, false));
        assertEquals("TCP4", Util.getProtocolName(6, 4, false));
        assertEquals("UDP4", Util.getProtocolName(17, 4, false));
        assertEquals("ESP4", Util.getProtocolName(50, 4, false));
        assertEquals("IGMP4", Util.getProtocolName(2, 4, false));
    }

    @Test
    public void briefNamesForKnownProtocols() {
        assertEquals("I4", Util.getProtocolName(1, 4, true));
        assertEquals("T4", Util.getProtocolName(6, 4, true));
        assertEquals("U4", Util.getProtocolName(17, 4, true));
    }

    @Test
    public void versionSuffixOmittedWhenZero() {
        assertEquals("TCP", Util.getProtocolName(6, 0, false));
        assertEquals("T", Util.getProtocolName(6, 0, true));
    }

    @Test
    public void unknownProtocolFallsBackToNumberAndVersion() {
        // Unknown protocols ignore the brief flag and report "<protocol>/<version>".
        assertEquals("99/4", Util.getProtocolName(99, 4, false));
        assertEquals("99/4", Util.getProtocolName(99, 4, true));
        assertEquals("255/6", Util.getProtocolName(255, 6, false));
    }
}
