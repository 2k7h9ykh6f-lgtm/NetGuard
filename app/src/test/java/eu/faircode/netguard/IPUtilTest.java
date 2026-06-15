package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2026 by Marcel Bokhorst (M66B)
*/

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 * Local JVM unit tests for {@link IPUtil}.
 *
 * <p>These run as Gradle local unit tests (src/test) on the host JVM, NOT on a device. They require
 * {@code testOptions.unitTests.returnDefaultValues = true} so the {@code android.util.Log} calls
 * inside {@link IPUtil#toCIDR} and {@link IPUtil.CIDR#CIDR(String, int)} return defaults instead of
 * throwing.
 *
 * <p>Scope note: {@code IPUtil} only does IPv4 range/CIDR math and address +/- 1. It has NO
 * isPrivate / isLoopback / isMulticast / isBroadcast classification, so the "well-known range"
 * tests below assert conversion correctness using those addresses as inputs, not classification.
 *
 * <p>All expected values were verified by executing the real {@code IPUtil} logic on OpenJDK 17.
 * Tests whose name starts with {@code characterize_} lock in the CURRENT (and in some cases
 * surprising) behavior for illegal input; see {@link #characterize_cidrFromInvalidString_*} and the
 * accompanying review notes for the proposed minimal fix.
 */
public class IPUtilTest {

    // ---- helpers ---------------------------------------------------------------------------------

    private static InetAddress ip(String s) throws UnknownHostException {
        return InetAddress.getByName(s);
    }

    private static String host(InetAddress a) {
        return a.getHostAddress();
    }

    /** Renders a CIDR as "address/prefix" using its stored (unmasked) address. */
    private static String render(IPUtil.CIDR c) {
        return c.address.getHostAddress() + "/" + c.prefix;
    }

    // ---- toCIDR: single-block results for the key prefixes ---------------------------------------
    // A start..end range that is exactly one aligned block must collapse to a single CIDR.

    @Test
    public void toCIDR_singleAddress_isSlash32() throws Exception {
        List<IPUtil.CIDR> r = IPUtil.toCIDR("10.0.0.0", "10.0.0.0");
        assertEquals(1, r.size());
        assertEquals("10.0.0.0/32", render(r.get(0)));
    }

    @Test
    public void toCIDR_twoAlignedAddresses_isSlash31() throws Exception {
        List<IPUtil.CIDR> r = IPUtil.toCIDR("10.0.0.0", "10.0.0.1");
        assertEquals(1, r.size());
        assertEquals("10.0.0.0/31", render(r.get(0)));
    }

    @Test
    public void toCIDR_fullThirdOctet_isSlash24() throws Exception {
        List<IPUtil.CIDR> r = IPUtil.toCIDR("10.0.0.0", "10.0.0.255");
        assertEquals(1, r.size());
        assertEquals("10.0.0.0/24", render(r.get(0)));
    }

    @Test
    public void toCIDR_fourAddresses_isSlash30() throws Exception {
        List<IPUtil.CIDR> r = IPUtil.toCIDR("192.168.1.0", "192.168.1.3");
        assertEquals(1, r.size());
        assertEquals("192.168.1.0/30", render(r.get(0)));
    }

    @Test
    public void toCIDR_upperHalf_isSlash1() throws Exception {
        List<IPUtil.CIDR> r = IPUtil.toCIDR("128.0.0.0", "255.255.255.255");
        assertEquals(1, r.size());
        assertEquals("128.0.0.0/1", render(r.get(0)));
    }

    @Test
    public void toCIDR_entireIpv4Space_isSlash0() throws Exception {
        // Exercises the /0 path including the floating-point log2 in toCIDR: log2(2^32) must
        // floor to 32 (verified), otherwise the range would wrongly split.
        List<IPUtil.CIDR> r = IPUtil.toCIDR("0.0.0.0", "255.255.255.255");
        assertEquals(1, r.size());
        assertEquals("0.0.0.0/0", render(r.get(0)));
    }

    // ---- toCIDR: ranges that must split into multiple CIDRs --------------------------------------

    @Test
    public void toCIDR_misalignedPair_splitsIntoTwoSlash32() throws Exception {
        // 192.168.1.1 is odd, so it cannot start a /31; the range splits into two host routes.
        List<IPUtil.CIDR> r = IPUtil.toCIDR("192.168.1.1", "192.168.1.2");
        assertEquals(2, r.size());
        assertEquals("192.168.1.1/32", render(r.get(0)));
        assertEquals("192.168.1.2/32", render(r.get(1)));
    }

    @Test
    public void toCIDR_sixAddresses_splitsIntoSlash30AndSlash31() throws Exception {
        List<IPUtil.CIDR> r = IPUtil.toCIDR("10.0.0.0", "10.0.0.5");
        assertEquals(2, r.size());
        assertEquals("10.0.0.0/30", render(r.get(0)));
        assertEquals("10.0.0.4/31", render(r.get(1)));
    }

    @Test
    public void toCIDR_misalignedSixAddresses_splitsIntoFour() throws Exception {
        List<IPUtil.CIDR> r = IPUtil.toCIDR("192.168.0.1", "192.168.0.6");
        assertEquals(4, r.size());
        assertEquals("192.168.0.1/32", render(r.get(0)));
        assertEquals("192.168.0.2/31", render(r.get(1)));
        assertEquals("192.168.0.4/31", render(r.get(2)));
        assertEquals("192.168.0.6/32", render(r.get(3)));
    }

    // ---- CIDR.getStart / getEnd across the boundary prefixes -------------------------------------

    @Test
    public void getStartEnd_slash32_isSingleAddress() {
        IPUtil.CIDR c = new IPUtil.CIDR("192.168.1.1", 32);
        assertEquals("192.168.1.1", host(c.getStart()));
        assertEquals("192.168.1.1", host(c.getEnd()));
    }

    @Test
    public void getStartEnd_slash31_masksOddAddressDown() {
        // An odd address with /31 must be masked down to the even block start.
        IPUtil.CIDR c = new IPUtil.CIDR("192.168.1.1", 31);
        assertEquals("192.168.1.0", host(c.getStart()));
        assertEquals("192.168.1.1", host(c.getEnd()));
    }

    @Test
    public void getStartEnd_slash24_coversFullThirdOctet() {
        IPUtil.CIDR c = new IPUtil.CIDR("192.168.1.130", 24);
        assertEquals("192.168.1.0", host(c.getStart()));
        assertEquals("192.168.1.255", host(c.getEnd()));
    }

    @Test
    public void getStartEnd_slash1_upperHalf() {
        IPUtil.CIDR c = new IPUtil.CIDR("192.168.1.1", 1);
        assertEquals("128.0.0.0", host(c.getStart()));
        assertEquals("255.255.255.255", host(c.getEnd()));
    }

    @Test
    public void getStartEnd_slash1_lowerHalf() {
        IPUtil.CIDR c = new IPUtil.CIDR("64.0.0.0", 1);
        assertEquals("0.0.0.0", host(c.getStart()));
        assertEquals("127.255.255.255", host(c.getEnd()));
    }

    @Test
    public void getStartEnd_slash0_coversEntireSpace() {
        // getEnd for /0 relies on 1L << 32 (a long shift). With an int shift this would be wrong;
        // this test guards that integer-overflow boundary.
        IPUtil.CIDR c = new IPUtil.CIDR("8.8.8.8", 0);
        assertEquals("0.0.0.0", host(c.getStart()));
        assertEquals("255.255.255.255", host(c.getEnd()));
    }

    // ---- Well-known ranges as INPUTS (conversion only -- IPUtil does not classify) ---------------

    @Test
    public void getStartEnd_privateLoopbackMulticastBroadcast_convertCorrectly() {
        // RFC1918 private blocks
        assertEquals("10.0.0.0", host(new IPUtil.CIDR("10.0.0.0", 8).getStart()));
        assertEquals("10.255.255.255", host(new IPUtil.CIDR("10.0.0.0", 8).getEnd()));
        assertEquals("172.16.0.0", host(new IPUtil.CIDR("172.16.0.0", 12).getStart()));
        assertEquals("172.31.255.255", host(new IPUtil.CIDR("172.16.0.0", 12).getEnd()));
        assertEquals("192.168.0.0", host(new IPUtil.CIDR("192.168.0.0", 16).getStart()));
        assertEquals("192.168.255.255", host(new IPUtil.CIDR("192.168.0.0", 16).getEnd()));
        // Loopback 127.0.0.0/8
        assertEquals("127.0.0.0", host(new IPUtil.CIDR("127.0.0.0", 8).getStart()));
        assertEquals("127.255.255.255", host(new IPUtil.CIDR("127.0.0.0", 8).getEnd()));
        // Multicast 224.0.0.0/4
        assertEquals("224.0.0.0", host(new IPUtil.CIDR("224.0.0.0", 4).getStart()));
        assertEquals("239.255.255.255", host(new IPUtil.CIDR("224.0.0.0", 4).getEnd()));
        // Limited broadcast 255.255.255.255/32
        assertEquals("255.255.255.255", host(new IPUtil.CIDR("255.255.255.255", 32).getStart()));
        assertEquals("255.255.255.255", host(new IPUtil.CIDR("255.255.255.255", 32).getEnd()));
    }

    // ---- minus1 / plus1, including the 32-bit overflow boundaries --------------------------------

    @Test
    public void plus1_minus1_normal() throws Exception {
        assertEquals("0.0.0.1", host(IPUtil.plus1(ip("0.0.0.0"))));
        assertEquals("0.0.0.0", host(IPUtil.minus1(ip("0.0.0.1"))));
    }

    @Test
    public void plus1_minus1_carryAcrossOctets() throws Exception {
        assertEquals("192.168.2.0", host(IPUtil.plus1(ip("192.168.1.255"))));
        assertEquals("192.168.1.255", host(IPUtil.minus1(ip("192.168.2.0"))));
    }

    @Test
    public void plus1_atMaxAddress_wrapsToZero() throws Exception {
        // Overflow boundary: 255.255.255.255 + 1 wraps to 0.0.0.0 (long2inet keeps low 32 bits).
        assertEquals("0.0.0.0", host(IPUtil.plus1(ip("255.255.255.255"))));
    }

    @Test
    public void minus1_atMinAddress_wrapsToMax() throws Exception {
        // Overflow boundary: 0.0.0.0 - 1 wraps to 255.255.255.255.
        assertEquals("255.255.255.255", host(IPUtil.minus1(ip("0.0.0.0"))));
    }

    // ---- compareTo: must use the full unsigned 32-bit value, not a signed int --------------------

    @Test
    public void compareTo_ordersAcrossSignBoundary() {
        // 0.0.0.0 < 255.255.255.255. A naive signed-int comparison would get this wrong because
        // 255.255.255.255 has the high bit set; IPUtil compares via long, which is correct.
        assertTrue(new IPUtil.CIDR("0.0.0.0", 0).compareTo(new IPUtil.CIDR("255.255.255.255", 0)) < 0);
        assertTrue(new IPUtil.CIDR("200.0.0.0", 0).compareTo(new IPUtil.CIDR("100.0.0.0", 0)) > 0);
    }

    @Test
    public void compareTo_equalAddressesAreZero() {
        assertEquals(0, new IPUtil.CIDR("10.0.0.5", 8).compareTo(new IPUtil.CIDR("10.0.0.5", 8)));
    }

    // ---- toString --------------------------------------------------------------------------------

    @Test
    public void toString_includesAddressPrefixAndRange() {
        assertEquals("192.168.1.130/24=192.168.1.0...192.168.1.255",
                new IPUtil.CIDR("192.168.1.130", 24).toString());
    }

    // ---- Illegal IP strings ----------------------------------------------------------------------
    // Numeric-but-invalid literals are used on purpose: alphabetic hostnames would trigger DNS
    // resolution (observed to be hijacked to a benchmark address in some environments), making the
    // test online-dependent and flaky.

    @Test
    public void toCIDR_illegalLiteral_throwsUnknownHostException() {
        assertThrows(UnknownHostException.class, () -> IPUtil.toCIDR("256.256.256.256", "1.2.3.4"));
        assertThrows(UnknownHostException.class, () -> IPUtil.toCIDR("1.2.3.4.5", "1.2.3.4"));
        assertThrows(UnknownHostException.class, () -> IPUtil.toCIDR("999.999.999.999", "1.2.3.4"));
        assertThrows(UnknownHostException.class, () -> IPUtil.toCIDR("300.1.1.1", "1.2.3.4"));
    }

    // ---- Leading zeros ---------------------------------------------------------------------------

    @Test
    public void leadingZeros_areParsedAsDecimal_onJvm() {
        // IMPORTANT platform caveat: on the host JVM (OpenJDK), leading zeros are DECIMAL, so
        // "010" == 10 and "192.168.000.001" == 192.168.0.1. Android's libcore resolver and many
        // C libraries instead treat a leading zero as OCTAL ("010" == 8). NetGuard parses such
        // strings on-device, so do NOT assume this JVM result matches runtime behavior for
        // zero-padded octets -- this test documents the JVM contract these local tests run under.
        assertEquals("192.168.0.1", host(new IPUtil.CIDR("192.168.000.001", 32).getStart()));
        assertEquals("10.0.0.1", host(new IPUtil.CIDR("010.0.0.1", 32).getStart()));
        assertEquals("192.168.1.10", host(new IPUtil.CIDR("192.168.1.010", 32).getStart()));
    }

    // ---- Characterization tests: CURRENT behavior on illegal input (candidate for a fix) ---------

    @Test
    public void characterize_emptyString_resolvesToLoopback() {
        // Gotcha: InetAddress.getByName("") returns the loopback address, so an empty rule string
        // silently becomes 127.0.0.1 rather than an error.
        assertEquals("127.0.0.1", host(new IPUtil.CIDR("", 32).getStart()));
    }

    @Test
    public void characterize_cidrFromInvalidString_leavesAddressNullAndPrefixZero() {
        // The CIDR(String,int) constructor catches UnknownHostException and logs it, but never
        // assigns address or prefix -- so both keep their defaults.
        IPUtil.CIDR c = new IPUtil.CIDR("256.256.256.256", 24);
        assertNull(c.address);
        assertEquals(0, c.prefix); // NOTE: the supplied prefix (24) is silently discarded.
    }

    @Test
    public void characterize_cidrFromInvalidString_getStartEndBehaveAsMatchAll() {
        // Because inet2long() null-guards, getStart()/getEnd() do NOT throw on a null address;
        // they return 0.0.0.0 .. 255.255.255.255 -- i.e. an invalid string silently degrades to a
        // "match every IPv4 address" range. For firewall rule evaluation this is the dangerous part.
        IPUtil.CIDR c = new IPUtil.CIDR("256.256.256.256", 24);
        assertEquals("0.0.0.0", host(c.getStart()));
        assertEquals("255.255.255.255", host(c.getEnd()));
    }

    @Test
    public void characterize_cidrFromInvalidString_toStringThrowsNpe() {
        // toString() dereferences the null address directly, so it DOES throw -- an inconsistency
        // with getStart()/getEnd() which silently succeed.
        IPUtil.CIDR c = new IPUtil.CIDR("256.256.256.256", 24);
        assertThrows(NullPointerException.class, c::toString);
    }
}
