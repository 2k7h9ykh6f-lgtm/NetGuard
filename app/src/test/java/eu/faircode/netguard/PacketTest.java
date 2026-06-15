package eu.faircode.netguard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PacketTest {

    @Test
    public void defaultFieldValues() {
        Packet p = new Packet();
        assertEquals(0L, p.time);
        assertEquals(0, p.version);
        assertEquals(0, p.protocol);
        assertNull(p.flags);
        assertNull(p.saddr);
        assertEquals(0, p.sport);
        assertNull(p.daddr);
        assertEquals(0, p.dport);
        assertNull(p.data);
        assertEquals(0, p.uid);
        assertFalse(p.allowed);
    }

    @Test
    public void toStringFormat() {
        Packet p = new Packet();
        p.uid = 1000;
        p.version = 4;
        p.protocol = 6;
        p.daddr = "1.2.3.4";
        p.dport = 443;
        assertEquals("uid=1000 v4 p6 1.2.3.4/443", p.toString());
    }

    @Test
    public void supportedProtocols() {
        assertTrue("ICMPv4", Packet.isSupportedProtocol(1));
        assertTrue("ICMPv6", Packet.isSupportedProtocol(58));
        assertTrue("TCP", Packet.isSupportedProtocol(6));
        assertTrue("UDP", Packet.isSupportedProtocol(17));
    }

    @Test
    public void unsupportedAndBoundaryProtocols() {
        // 0 (HOPOPT), 2 (IGMP), 50 (ESP), neighbours of supported numbers,
        // and out-of-range / negative values must all be rejected.
        int[] unsupported = {0, 2, 50, 255, 256, -1, 5, 7, 16, 18, 57, 59};
        for (int protocol : unsupported)
            assertFalse("protocol " + protocol + " should be unsupported",
                    Packet.isSupportedProtocol(protocol));
    }
}
