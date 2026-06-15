package eu.faircode.netguard;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Unit tests for {@link Packet} — pure Java POJO, no Android dependencies.
 */
public class PacketTest {

    @Test
    public void defaultConstructor_fieldsInitialized() {
        Packet p = new Packet();
        assertEquals(0, p.time);
        assertEquals(0, p.version);
        assertEquals(0, p.protocol);
        assertNull(p.flags);
        assertNull(p.saddr);
        assertEquals(0, p.sport);
        assertNull(p.daddr);
        assertEquals(0, p.dport);
        assertNull(p.data);
        assertEquals(0, p.uid);
        assertEquals(false, p.allowed);
    }

    @Test
    public void toString_containsExpectedFields() {
        Packet p = new Packet();
        p.uid = 1000;
        p.version = 4;
        p.protocol = 6;
        p.daddr = "192.168.1.1";
        p.dport = 443;

        String str = p.toString();
        assertEquals("uid=1000 v4 p6 192.168.1.1/443", str);
    }

    @Test
    public void fieldAssignment_roundTrips() {
        Packet p = new Packet();
        p.time = 1234567890L;
        p.version = 6;
        p.protocol = 17;
        p.flags = "SA";
        p.saddr = "10.0.0.1";
        p.sport = 12345;
        p.daddr = "8.8.8.8";
        p.dport = 53;
        p.data = "dns-query";
        p.uid = 10086;
        p.allowed = true;

        assertEquals(1234567890L, p.time);
        assertEquals(6, p.version);
        assertEquals(17, p.protocol);
        assertEquals("SA", p.flags);
        assertEquals("10.0.0.1", p.saddr);
        assertEquals(12345, p.sport);
        assertEquals("8.8.8.8", p.daddr);
        assertEquals(53, p.dport);
        assertEquals("dns-query", p.data);
        assertEquals(10086, p.uid);
        assertEquals(true, p.allowed);
    }
}
