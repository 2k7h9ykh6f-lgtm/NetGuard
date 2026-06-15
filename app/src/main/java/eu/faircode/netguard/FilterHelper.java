package eu.faircode.netguard;

import java.util.Map;

/**
 * Pure-Java utility classes extracted from {@link ServiceSinkhole} for
 * testability. Contains protocol support checks, domain blocking lookups,
 * and the {@link IPKey}/{@link IPRule} data structures used by the
 * IP-level filter.
 */
public final class FilterHelper {

    private FilterHelper() {
    }

    // ---- Protocol support ------------------------------------------------

    /** IANA protocol number for ICMPv4. */
    public static final int PROTO_ICMP = 1;
    /** IANA protocol number for TCP. */
    public static final int PROTO_TCP = 6;
    /** IANA protocol number for UDP. */
    public static final int PROTO_UDP = 17;
    /** IANA protocol number for ICMPv6. */
    public static final int PROTO_ICMPV6 = 58;

    /**
     * Returns {@code true} if the given IANA protocol number is one that
     * NetGuard explicitly handles (ICMP, ICMPv6, TCP, UDP).
     */
    public static boolean isSupported(int protocol) {
        return protocol == PROTO_ICMP
                || protocol == PROTO_ICMPV6
                || protocol == PROTO_TCP
                || protocol == PROTO_UDP;
    }

    // ---- Domain blocking -------------------------------------------------

    /**
     * Check whether a domain name is in the blocked-hosts map.
     *
     * @param name     the domain to look up
     * @param hostsMap the blocked-hosts map (domain &rarr; blocked flag)
     * @return {@code true} if the domain is present and its value is
     *         {@code true}
     */
    public static boolean isDomainBlocked(String name, Map<String, Boolean> hostsMap) {
        if (name == null || hostsMap == null) {
            return false;
        }
        Boolean value = hostsMap.get(name);
        return value != null && value;
    }

    // ---- IPKey -----------------------------------------------------------

    /**
     * Composite key for IP-level filter lookups, extracted from
     * {@code ServiceSinkhole.IPKey}.
     *
     * <p>Only TCP and UDP use port numbers; for other protocols the port
     * is normalised to zero so that lookups match correctly.</p>
     */
    public static final class IPKey {
        public final int version;
        public final int protocol;
        public final int dport;
        public final int uid;

        public IPKey(int version, int protocol, int dport, int uid) {
            this.version = version;
            this.protocol = protocol;
            // Only TCP (6) and UDP (17) have port numbers
            this.dport = (protocol == PROTO_TCP || protocol == PROTO_UDP) ? dport : 0;
            this.uid = uid;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof IPKey)) {
                return false;
            }
            IPKey other = (IPKey) obj;
            return this.version == other.version
                    && this.protocol == other.protocol
                    && this.dport == other.dport
                    && this.uid == other.uid;
        }

        @Override
        public int hashCode() {
            return (version << 24) ^ (protocol << 16) ^ (dport << 8) ^ uid;
        }

        @Override
        public String toString() {
            return "v" + version + " p" + protocol + " port=" + dport + " uid=" + uid;
        }
    }

    // ---- IPRule ----------------------------------------------------------

    /**
     * A filter rule associated with a resolved IP address, extracted from
     * {@code ServiceSinkhole.IPRule}.
     */
    public static final class IPRule {
        private final IPKey key;
        private final String name;
        private final boolean block;
        private long time;
        private long ttl;

        public IPRule(IPKey key, String name, boolean block, long time, long ttl) {
            this.key = key;
            this.name = name;
            this.block = block;
            this.time = time;
            this.ttl = ttl;
        }

        public boolean isBlocked() {
            return block;
        }

        /**
         * A rule is expired when the current time exceeds
         * {@code time + ttl * 2} (the original uses a 2x grace period).
         */
        public boolean isExpired() {
            return System.currentTimeMillis() > (time + ttl * 2);
        }

        /**
         * A rule is expired at the given timestamp.
         * Useful for deterministic testing without relying on wall clock.
         */
        public boolean isExpiredAt(long currentTimeMillis) {
            return currentTimeMillis > (time + ttl * 2);
        }

        public void updateExpires(long time, long ttl) {
            this.time = time;
            this.ttl = ttl;
        }

        public IPKey getKey() {
            return key;
        }

        public String getName() {
            return name;
        }

        public long getTime() {
            return time;
        }

        public long getTtl() {
            return ttl;
        }

        @Override
        public String toString() {
            return key + " " + name;
        }
    }
}
