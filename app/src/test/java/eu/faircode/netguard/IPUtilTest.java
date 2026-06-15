package eu.faircode.netguard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.net.InetAddress;
import java.util.List;

public class IPUtilTest {

    // Numeric literals are parsed without any DNS lookup, so these stay offline.
    private static InetAddress ip(String s) throws Exception {
        return InetAddress.getByName(s);
    }

    private static long toLong(InetAddress addr) {
        long result = 0;
        for (byte b : addr.getAddress())
            result = (result << 8) | (b & 0xFF);
        return result;
    }

    // Asserts the CIDR list contiguously tiles [start, end] with no gaps/overlaps.
    private static void assertTiles(InetAddress start, InetAddress end, List<IPUtil.CIDR> cidrs) {
        assertFalse("expected at least one CIDR", cidrs.isEmpty());
        assertEquals("first block must start at range start",
                toLong(start), toLong(cidrs.get(0).getStart()));
        assertEquals("last block must end at range end",
                toLong(end), toLong(cidrs.get(cidrs.size() - 1).getEnd()));
        for (int i = 1; i < cidrs.size(); i++)
            assertEquals("blocks must be contiguous",
                    toLong(cidrs.get(i - 1).getEnd()) + 1, toLong(cidrs.get(i).getStart()));
    }

    @Test
    public void singleAddressYieldsHostRoute() throws Exception {
        InetAddress a = ip("10.0.0.1");
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR(a, a);
        assertEquals(1, cidrs.size());
        assertEquals(32, cidrs.get(0).prefix);
        assertTiles(a, a, cidrs);
    }

    @Test
    public void alignedRangeTilesExactly() throws Exception {
        InetAddress start = ip("10.0.0.0");
        InetAddress end = ip("10.0.0.3");
        assertTiles(start, end, IPUtil.toCIDR(start, end));
    }

    @Test
    public void classCRangeTiles() throws Exception {
        InetAddress start = ip("10.0.0.0");
        InetAddress end = ip("10.0.0.255");
        assertTiles(start, end, IPUtil.toCIDR(start, end));
    }

    @Test
    public void unalignedRangeTilesWithMultipleBlocks() throws Exception {
        InetAddress start = ip("10.0.0.1");
        InetAddress end = ip("10.0.0.6");
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR(start, end);
        assertTrue("an unaligned range needs several blocks", cidrs.size() > 1);
        assertTiles(start, end, cidrs);
    }

    @Test
    public void reversedRangeYieldsEmptyList() throws Exception {
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR(ip("10.0.0.5"), ip("10.0.0.1"));
        assertTrue("start after end must produce no CIDRs", cidrs.isEmpty());
    }

    @Test
    public void cidrStartAndEndAreMaskAligned() throws Exception {
        IPUtil.CIDR block = new IPUtil.CIDR("10.0.0.5", 24);
        assertEquals(toLong(ip("10.0.0.0")), toLong(block.getStart()));
        assertEquals(toLong(ip("10.0.0.255")), toLong(block.getEnd()));

        IPUtil.CIDR host = new IPUtil.CIDR("10.0.0.7", 32);
        assertEquals(toLong(ip("10.0.0.7")), toLong(host.getStart()));
        assertEquals(toLong(ip("10.0.0.7")), toLong(host.getEnd()));
    }

    @Test
    public void plusAndMinusOneWithCarry() throws Exception {
        assertEquals(toLong(ip("10.0.0.2")), toLong(IPUtil.plus1(ip("10.0.0.1"))));
        assertEquals(toLong(ip("10.0.0.0")), toLong(IPUtil.minus1(ip("10.0.0.1"))));
        // Octet carry / borrow.
        assertEquals(toLong(ip("10.0.1.0")), toLong(IPUtil.plus1(ip("10.0.0.255"))));
        assertEquals(toLong(ip("10.0.0.255")), toLong(IPUtil.minus1(ip("10.0.1.0"))));
    }

    @Test
    public void compareToOrdersByAddress() throws Exception {
        IPUtil.CIDR lower = new IPUtil.CIDR("10.0.0.1", 32);
        IPUtil.CIDR higher = new IPUtil.CIDR("10.0.0.2", 32);
        assertTrue(lower.compareTo(higher) < 0);
        assertTrue(higher.compareTo(lower) > 0);
        assertEquals(0, lower.compareTo(new IPUtil.CIDR("10.0.0.1", 32)));
    }
}
