package eu.faircode.netguard;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link Forward} — pure Java POJO, no Android dependencies.
 */
public class ForwardTest {

    @Test
    public void defaultValues_allZeroOrNull() {
        Forward f = new Forward();
        assertEquals(0, f.protocol);
        assertEquals(0, f.dport);
        assertEquals(null, f.raddr);
        assertEquals(0, f.rport);
        assertEquals(0, f.ruid);
    }

    @Test
    public void toString_containsAllFields() {
        Forward f = new Forward();
        f.protocol = 6;
        f.dport = 8080;
        f.raddr = "10.0.0.5";
        f.rport = 80;
        f.ruid = 1000;

        String str = f.toString();
        assertTrue(str.contains("protocol=6"));
        assertTrue(str.contains("8080"));
        assertTrue(str.contains("10.0.0.5"));
        assertTrue(str.contains("80"));
        assertTrue(str.contains("1000"));
    }

    @Test
    public void fieldAssignment_roundTrips() {
        Forward f = new Forward();
        f.protocol = 17;
        f.dport = 5353;
        f.raddr = "192.168.0.1";
        f.rport = 53;
        f.ruid = 10086;

        assertEquals(17, f.protocol);
        assertEquals(5353, f.dport);
        assertEquals("192.168.0.1", f.raddr);
        assertEquals(53, f.rport);
        assertEquals(10086, f.ruid);
    }
}
