package eu.faircode.netguard;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * JVM unit tests for {@link FilterHelper}, covering:
 * <ul>
 *   <li>{@link FilterHelper#isSupported(int)} — protocol support check</li>
 *   <li>{@link FilterHelper#isDomainBlocked(String, Map)} — domain blocking lookup</li>
 *   <li>{@link FilterHelper.IPKey} — equality, hash code, port normalisation</li>
 *   <li>{@link FilterHelper.IPRule} — isBlocked, isExpired, isExpiredAt</li>
 * </ul>
 */
public class FilterHelperTest {

    // ========================================================================
    // isSupported
    // ========================================================================

    @Test
    public void isSupported_icmp() {
        assertTrue(FilterHelper.isSupported(1));
    }

    @Test
    public void isSupported_tcp() {
        assertTrue(FilterHelper.isSupported(6));
    }

    @Test
    public void isSupported_udp() {
        assertTrue(FilterHelper.isSupported(17));
    }

    @Test
    public void isSupported_icmpv6() {
        assertTrue(FilterHelper.isSupported(58));
    }

    @Test
    public void isSupported_unknownProtocols() {
        assertFalse(FilterHelper.isSupported(0));   // HOPOPTS
        assertFalse(FilterHelper.isSupported(2));   // IGMP
        assertFalse(FilterHelper.isSupported(47));  // GRE
        assertFalse(FilterHelper.isSupported(50));  // ESP
        assertFalse(FilterHelper.isSupported(51));  // AH
        assertFalse(FilterHelper.isSupported(132)); // SCTP
        assertFalse(FilterHelper.isSupported(255)); // raw
        assertFalse(FilterHelper.isSupported(-1));
    }

    // ========================================================================
    // isDomainBlocked
    // ========================================================================

    @Test
    public void isDomainBlocked_blockedDomain() {
        Map<String, Boolean> map = new HashMap<>();
        map.put("ads.example.com", true);
        assertTrue(FilterHelper.isDomainBlocked("ads.example.com", map));
    }

    @Test
    public void isDomainBlocked_notInMap() {
        Map<String, Boolean> map = new HashMap<>();
        map.put("ads.example.com", true);
        assertFalse(FilterHelper.isDomainBlocked("safe.example.com", map));
    }

    @Test
    public void isDomainBlocked_inMapButFalse() {
        Map<String, Boolean> map = new HashMap<>();
        map.put("example.com", false);
        assertFalse(FilterHelper.isDomainBlocked("example.com", map));
    }

    @Test
    public void isDomainBlocked_emptyMap() {
        Map<String, Boolean> map = new HashMap<>();
        assertFalse(FilterHelper.isDomainBlocked("anything.com", map));
    }

    @Test
    public void isDomainBlocked_nullName() {
        Map<String, Boolean> map = new HashMap<>();
        map.put("test.com", true);
        assertFalse(FilterHelper.isDomainBlocked(null, map));
    }

    @Test
    public void isDomainBlocked_nullMap() {
        assertFalse(FilterHelper.isDomainBlocked("test.com", null));
    }

    @Test
    public void isDomainBlocked_nullBoth() {
        assertFalse(FilterHelper.isDomainBlocked(null, null));
    }

    @Test
    public void isDomainBlocked_caseSensitive() {
        Map<String, Boolean> map = new HashMap<>();
        map.put("ads.Example.COM", true);
        // Domain matching should be case-sensitive (as in the original)
        assertFalse(FilterHelper.isDomainBlocked("ads.example.com", map));
        assertTrue(FilterHelper.isDomainBlocked("ads.Example.COM", map));
    }

    @Test
    public void isDomainBlocked_subdomainNotMatched() {
        Map<String, Boolean> map = new HashMap<>();
        map.put("example.com", true);
        // No wildcard — subdomain should not match
        assertFalse(FilterHelper.isDomainBlocked("sub.example.com", map));
    }

    // ========================================================================
    // IPKey
    // ========================================================================

    @Test
    public void ipKey_equalsSame() {
        FilterHelper.IPKey a = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPKey b = new FilterHelper.IPKey(4, 6, 80, 1000);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    public void ipKey_notEqualDifferentVersion() {
        FilterHelper.IPKey a = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPKey b = new FilterHelper.IPKey(6, 6, 80, 1000);
        assertNotEquals(a, b);
    }

    @Test
    public void ipKey_notEqualDifferentProtocol() {
        FilterHelper.IPKey a = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPKey b = new FilterHelper.IPKey(4, 17, 80, 1000);
        assertNotEquals(a, b);
    }

    @Test
    public void ipKey_notEqualDifferentPort() {
        FilterHelper.IPKey a = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPKey b = new FilterHelper.IPKey(4, 6, 443, 1000);
        assertNotEquals(a, b);
    }

    @Test
    public void ipKey_notEqualDifferentUid() {
        FilterHelper.IPKey a = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPKey b = new FilterHelper.IPKey(4, 6, 80, 2000);
        assertNotEquals(a, b);
    }

    @Test
    public void ipKey_portNormalisedForIcmp() {
        // ICMP (protocol 1) should normalise port to 0
        FilterHelper.IPKey a = new FilterHelper.IPKey(4, 1, 1234, 100);
        FilterHelper.IPKey b = new FilterHelper.IPKey(4, 1, 5678, 100);
        assertEquals(a, b); // different ports but both normalised to 0
        assertEquals(0, a.dport);
        assertEquals(0, b.dport);
    }

    @Test
    public void ipKey_portNormalisedForIcmpv6() {
        // ICMPv6 (protocol 58) should normalise port to 0
        FilterHelper.IPKey a = new FilterHelper.IPKey(6, 58, 999, 200);
        assertEquals(0, a.dport);
    }

    @Test
    public void ipKey_portPreservedForTcp() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 443, 1000);
        assertEquals(443, key.dport);
    }

    @Test
    public void ipKey_portPreservedForUdp() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 17, 53, 1000);
        assertEquals(53, key.dport);
    }

    @Test
    public void ipKey_notEqualToNull() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        assertNotEquals(key, null);
    }

    @Test
    public void ipKey_notEqualToOtherType() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        assertNotEquals(key, "not an IPKey");
    }

    @Test
    public void ipKey_hashCodeConsistency() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        int hash1 = key.hashCode();
        int hash2 = key.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    public void ipKey_hashCodeUsableInMap() {
        Map<FilterHelper.IPKey, String> map = new HashMap<>();
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        map.put(key, "test");
        FilterHelper.IPKey lookup = new FilterHelper.IPKey(4, 6, 80, 1000);
        assertEquals("test", map.get(lookup));
    }

    @Test
    public void ipKey_toString() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 443, 1000);
        String str = key.toString();
        assertTrue(str.contains("v4"));
        assertTrue(str.contains("p6"));
        assertTrue(str.contains("443"));
        assertTrue(str.contains("1000"));
    }

    // ========================================================================
    // IPRule
    // ========================================================================

    @Test
    public void ipRule_isBlocked_true() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "ads.com", true, 1000, 3600);
        assertTrue(rule.isBlocked());
    }

    @Test
    public void ipRule_isBlocked_false() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "safe.com", false, 1000, 3600);
        assertFalse(rule.isBlocked());
    }

    @Test
    public void ipRule_notExpired() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        long now = System.currentTimeMillis();
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "test.com", true, now, 3600_000);

        // time + ttl*2 = now + 7200000 — should not be expired
        assertFalse(rule.isExpired());
    }

    @Test
    public void ipRule_expired() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        long past = System.currentTimeMillis() - 10_000_000;
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "test.com", true, past, 1000);

        // time + ttl*2 = past + 2000 — well in the past
        assertTrue(rule.isExpired());
    }

    @Test
    public void ipRule_isExpiredAt_deterministic() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "test.com", true, 1000, 500);

        // expires at 1000 + 500*2 = 2000
        assertFalse(rule.isExpiredAt(1999));  // just before expiry
        assertFalse(rule.isExpiredAt(2000));  // exactly at boundary (not strictly greater)
        assertTrue(rule.isExpiredAt(2001));   // just after expiry
    }

    @Test
    public void ipRule_isExpiredAt_zeroTtl() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "test.com", true, 1000, 0);

        // expires at 1000 + 0 = 1000
        assertFalse(rule.isExpiredAt(1000));
        assertTrue(rule.isExpiredAt(1001));
    }

    @Test
    public void ipRule_updateExpires() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "test.com", true, 0, 1);

        // Initially expired at any time > 2
        assertTrue(rule.isExpiredAt(3));

        // Update to far future
        rule.updateExpires(999999, 999999);
        assertFalse(rule.isExpiredAt(1000000));
    }

    @Test
    public void ipRule_getters() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 443, 1000);
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "example.com", true, 5000, 300);

        assertEquals(key, rule.getKey());
        assertEquals("example.com", rule.getName());
        assertEquals(5000, rule.getTime());
        assertEquals(300, rule.getTtl());
    }

    @Test
    public void ipRule_toString() {
        FilterHelper.IPKey key = new FilterHelper.IPKey(4, 6, 80, 1000);
        FilterHelper.IPRule rule = new FilterHelper.IPRule(key, "test.com", true, 1000, 500);
        String str = rule.toString();
        assertTrue(str.contains("test.com"));
    }
}
