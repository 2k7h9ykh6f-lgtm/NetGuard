package eu.faircode.netguard;

import org.junit.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link IPUtil} — plain JUnit with returnDefaultValues = true
 * configured in build.gradle testOptions, so android.util.Log calls return
 * default values instead of throwing.
 *
 * These tests verify IP/CIDR conversion logic without any network, VPN,
 * signing-key, or Robolectric dependencies.
 */
public class IPUtilTest {

    // ── CIDR range conversion ────────────────────────────────────────

    @Test
    public void toCIDR_singleHost_producesSlash32() throws Exception {
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR("10.0.0.1", "10.0.0.1");
        assertEquals(1, cidrs.size());
        assertEquals(32, cidrs.get(0).prefix);
        assertEquals("10.0.0.1", cidrs.get(0).address.getHostAddress());
    }

    @Test
    public void toCIDR_classCBlock_producesSingleSlash24() throws Exception {
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR("192.168.1.0", "192.168.1.255");
        assertEquals(1, cidrs.size());
        assertEquals(24, cidrs.get(0).prefix);
    }

    @Test
    public void toCIDR_twoAddresses_producesTwoSlash32() throws Exception {
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR("10.0.0.1", "10.0.0.2");
        assertEquals(2, cidrs.size());
        // Each should be a /32
        for (IPUtil.CIDR cidr : cidrs) {
            assertEquals(32, cidr.prefix);
        }
    }

    @Test
    public void toCIDR_classABlock_producesSingleSlash8() throws Exception {
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR("10.0.0.0", "10.255.255.255");
        assertEquals(1, cidrs.size());
        assertEquals(8, cidrs.get(0).prefix);
    }

    @Test
    public void toCIDR_nonAlignedRange_producesMultipleCIDRs() throws Exception {
        // 10.0.0.1 - 10.0.0.6 should produce multiple CIDRs
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR("10.0.0.1", "10.0.0.6");
        assertTrue("Expected more than 1 CIDR for non-aligned range", cidrs.size() > 1);
    }

    // ── CIDR start/end calculation ───────────────────────────────────

    @Test
    public void cidr_getStartAndEnd_slash24() throws Exception {
        IPUtil.CIDR cidr = new IPUtil.CIDR("192.168.1.0", 24);
        assertNotNull(cidr.getStart());
        assertNotNull(cidr.getEnd());
        assertEquals("192.168.1.0", cidr.getStart().getHostAddress());
        assertEquals("192.168.1.255", cidr.getEnd().getHostAddress());
    }

    @Test
    public void cidr_getStartAndEnd_slash32() throws Exception {
        IPUtil.CIDR cidr = new IPUtil.CIDR("1.2.3.4", 32);
        assertEquals("1.2.3.4", cidr.getStart().getHostAddress());
        assertEquals("1.2.3.4", cidr.getEnd().getHostAddress());
    }

    @Test
    public void cidr_getStartAndEnd_slash16() throws Exception {
        IPUtil.CIDR cidr = new IPUtil.CIDR("172.16.0.0", 16);
        assertEquals("172.16.0.0", cidr.getStart().getHostAddress());
        assertEquals("172.16.255.255", cidr.getEnd().getHostAddress());
    }

    @Test
    public void cidr_getStartAndEnd_slash0() throws Exception {
        IPUtil.CIDR cidr = new IPUtil.CIDR("0.0.0.0", 0);
        assertEquals("0.0.0.0", cidr.getStart().getHostAddress());
        assertEquals("255.255.255.255", cidr.getEnd().getHostAddress());
    }

    // ── plus1 / minus1 ───────────────────────────────────────────────

    @Test
    public void plus1_incrementsAddress() throws Exception {
        InetAddress addr = InetAddress.getByName("10.0.0.1");
        InetAddress next = IPUtil.plus1(addr);
        assertEquals("10.0.0.2", next.getHostAddress());
    }

    @Test
    public void minus1_decrementsAddress() throws Exception {
        InetAddress addr = InetAddress.getByName("10.0.0.2");
        InetAddress prev = IPUtil.minus1(addr);
        assertEquals("10.0.0.1", prev.getHostAddress());
    }

    @Test
    public void plus1_crossesOctetBoundary() throws Exception {
        InetAddress addr = InetAddress.getByName("10.0.0.255");
        InetAddress next = IPUtil.plus1(addr);
        assertEquals("10.0.1.0", next.getHostAddress());
    }

    @Test
    public void minus1_crossesOctetBoundary() throws Exception {
        InetAddress addr = InetAddress.getByName("10.0.1.0");
        InetAddress prev = IPUtil.minus1(addr);
        assertEquals("10.0.0.255", prev.getHostAddress());
    }

    // ── CIDR compareTo ───────────────────────────────────────────────

    @Test
    public void cidr_compareTo_lowerAddressFirst() {
        IPUtil.CIDR a = new IPUtil.CIDR("10.0.0.0", 24);
        IPUtil.CIDR b = new IPUtil.CIDR("192.168.0.0", 24);
        assertTrue(a.compareTo(b) < 0);
        assertTrue(b.compareTo(a) > 0);
    }

    @Test
    public void cidr_compareTo_equalAddresses() {
        IPUtil.CIDR a = new IPUtil.CIDR("10.0.0.0", 24);
        IPUtil.CIDR b = new IPUtil.CIDR("10.0.0.0", 8);
        assertEquals(0, a.compareTo(b));
    }

    // ── toString ─────────────────────────────────────────────────────

    @Test
    public void cidr_toString_containsRangeInfo() {
        IPUtil.CIDR cidr = new IPUtil.CIDR("192.168.1.0", 24);
        String str = cidr.toString();
        assertTrue(str.contains("192.168.1.0"));
        assertTrue(str.contains("/24"));
        assertTrue(str.contains("192.168.1.255"));
    }
}
