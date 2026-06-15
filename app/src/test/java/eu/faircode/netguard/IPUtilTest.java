package eu.faircode.netguard;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import java.net.InetAddress;
import java.util.List;

/**
 * Local JVM smoke test for {@link IPUtil}.
 *
 * <p>This is intentionally the minimal, stable seed of NetGuard's test
 * infrastructure. It exercises pure IP/CIDR arithmetic and deliberately:
 * <ul>
 *     <li>requires no release signing keystore (runs on a fresh checkout),</li>
 *     <li>requires no VPN permission or Android device/emulator,</li>
 *     <li>performs no network/DNS access — only dotted-quad IPv4 literals are
 *         used, which {@link InetAddress#getByName(String)} parses locally
 *         without a lookup.</li>
 * </ul>
 *
 * <p>It relies on {@code testOptions.unitTests.returnDefaultValues = true} so
 * that {@code android.util.Log} calls inside {@link IPUtil} are no-ops rather
 * than throwing under the android.jar stubs.
 */
public class IPUtilTest {

    @Test
    public void toCIDR_collapsesAlignedRangeToSingleBlock() throws Exception {
        // A full, aligned /24 range must collapse to exactly one CIDR block.
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR("10.0.0.0", "10.0.0.255");

        assertEquals("aligned /24 range should yield one CIDR", 1, cidrs.size());

        IPUtil.CIDR cidr = cidrs.get(0);
        assertEquals(24, cidr.prefix);
        assertEquals("10.0.0.0", cidr.address.getHostAddress());
        assertEquals("10.0.0.0", cidr.getStart().getHostAddress());
        assertEquals("10.0.0.255", cidr.getEnd().getHostAddress());
    }

    @Test
    public void toCIDR_splitsUnalignedRangeIntoMultipleBlocks() throws Exception {
        // A range that is not a single power-of-two block must be split, and the
        // blocks must exactly cover the requested [start, end] interval.
        List<IPUtil.CIDR> cidrs = IPUtil.toCIDR("10.0.0.1", "10.0.0.254");

        assertFalse("unaligned range should produce at least one block", cidrs.isEmpty());
        assertEquals("first block must start at the range start",
                "10.0.0.1", cidrs.get(0).getStart().getHostAddress());
        assertEquals("last block must end at the range end",
                "10.0.0.254", cidrs.get(cidrs.size() - 1).getEnd().getHostAddress());
    }

    @Test
    public void cidr_startAndEndBoundsAreComputedFromPrefix() throws Exception {
        // getStart()/getEnd() derive the network boundaries from the prefix.
        IPUtil.CIDR cidr = new IPUtil.CIDR("172.16.5.0", 24);

        assertEquals("172.16.5.0", cidr.getStart().getHostAddress());
        assertEquals("172.16.5.255", cidr.getEnd().getHostAddress());
    }

    @Test
    public void plusOneAndMinusOne_walkAdjacentAddresses() throws Exception {
        InetAddress base = InetAddress.getByName("10.0.0.1");

        assertEquals("10.0.0.2", IPUtil.plus1(base).getHostAddress());
        assertEquals("10.0.0.0", IPUtil.minus1(base).getHostAddress());
    }
}
