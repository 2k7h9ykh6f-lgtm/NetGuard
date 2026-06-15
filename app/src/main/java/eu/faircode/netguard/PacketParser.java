package eu.faircode.netguard;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Pure-Java IP packet parser that mirrors the native C parsing logic in
 * {@code jni/netguard/ip.c:handle_ip()}, but with proper bounds checking.
 *
 * <p>This class is intentionally free of Android dependencies so it can be
 * exercised in plain JVM unit tests.</p>
 */
public final class PacketParser {

    // IANA protocol numbers
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;
    public static final int PROTO_ICMPV6 = 58;

    // Minimum header sizes
    private static final int IPV4_HEADER_MIN = 20;
    private static final int IPV6_HEADER_SIZE = 40;
    private static final int ICMP_MINLEN = 8;
    private static final int UDP_HEADER_SIZE = 8;
    private static final int TCP_HEADER_MIN = 20;

    private PacketParser() {
    }

    /**
     * Thrown when a packet is structurally invalid (too short, bad IHL, etc.).
     */
    public static class PacketParseException extends Exception {
        public PacketParseException(String message) {
            super(message);
        }
    }

    /**
     * Parse a raw IP packet (as would be read from a TUN device) into a
     * {@link Packet} object.
     *
     * @param raw the raw packet bytes
     * @return a populated {@link Packet}, or {@code null} if the packet is
     *         structurally invalid (mirrors the C code which silently returns)
     * @throws PacketParseException if the packet is malformed in a way that
     *         the C parser would also reject
     */
    public static Packet parse(byte[] raw) throws PacketParseException {
        if (raw == null || raw.length == 0) {
            throw new PacketParseException("Empty packet");
        }

        int version = (raw[0] & 0xFF) >> 4;

        if (version == 4) {
            return parseIPv4(raw);
        } else if (version == 6) {
            return parseIPv6(raw);
        } else {
            throw new PacketParseException("Unknown IP version: " + version);
        }
    }

    private static Packet parseIPv4(byte[] raw) throws PacketParseException {
        if (raw.length < IPV4_HEADER_MIN) {
            throw new PacketParseException(
                    "IPv4 packet too short: " + raw.length + " < " + IPV4_HEADER_MIN);
        }

        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);

        int ihl = raw[0] & 0x0F;

        // Validate IHL: must be >= 5 (20 bytes minimum)
        if (ihl < 5) {
            throw new PacketParseException("IPv4 IHL too small: " + ihl + " (minimum 5)");
        }

        int headerLen = ihl * 4;
        if (raw.length < headerLen) {
            throw new PacketParseException(
                    "IPv4 packet shorter than header: " + raw.length + " < " + headerLen);
        }

        int totLen = buf.getShort(2) & 0xFFFF;
        if (totLen != raw.length) {
            throw new PacketParseException(
                    "IPv4 tot_len mismatch: header says " + totLen + " but actual " + raw.length);
        }

        // Check for IP fragments (MF bit or fragment offset)
        int fragOff = buf.getShort(6) & 0xFFFF;
        boolean mf = (fragOff & 0x2000) != 0;
        int fragOffset = (fragOff & 0x1FFF) * 8;
        if (mf || fragOffset > 0) {
            throw new PacketParseException("IP fragment not supported (offset=" + fragOffset + ", MF=" + mf + ")");
        }

        int protocol = buf.get(9) & 0xFF;

        // Source address: bytes 12-15
        byte[] srcBytes = new byte[4];
        buf.position(12);
        buf.get(srcBytes);
        String saddr = inet4ToString(srcBytes);

        // Destination address: bytes 16-19
        byte[] dstBytes = new byte[4];
        buf.get(dstBytes);
        String daddr = inet4ToString(dstBytes);

        int payloadOffset = headerLen;
        return parsePayload(raw, payloadOffset, protocol, 4, saddr, daddr);
    }

    private static Packet parseIPv6(byte[] raw) throws PacketParseException {
        if (raw.length < IPV6_HEADER_SIZE) {
            throw new PacketParseException(
                    "IPv6 packet too short: " + raw.length + " < " + IPV6_HEADER_SIZE);
        }

        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);

        int protocol = buf.get(6) & 0xFF;

        // Source address: bytes 8-23
        byte[] srcBytes = new byte[16];
        buf.position(8);
        buf.get(srcBytes);
        String saddr = inet6ToString(srcBytes);

        // Destination address: bytes 24-39
        byte[] dstBytes = new byte[16];
        buf.get(dstBytes);
        String daddr = inet6ToString(dstBytes);

        // Skip extension headers (simplified: walk known next-header chain)
        int payloadOffset = IPV6_HEADER_SIZE;
        int nextHeader = protocol;
        int maxIterations = 10; // guard against infinite loops
        while (isLowerLayer(nextHeader) && !isUpperLayer(nextHeader) && maxIterations-- > 0) {
            if (payloadOffset + 2 > raw.length) {
                break;
            }
            nextHeader = raw[payloadOffset] & 0xFF;
            int extLen = (raw[payloadOffset + 1] & 0xFF) + 1; // ext header length in 8-byte units
            payloadOffset += extLen * 8;
            protocol = nextHeader;
        }

        if (payloadOffset > raw.length) {
            throw new PacketParseException("IPv6 extension headers exceed packet length");
        }

        return parsePayload(raw, payloadOffset, protocol, 6, saddr, daddr);
    }

    private static Packet parsePayload(byte[] raw, int payloadOffset,
                                        int protocol, int version,
                                        String saddr, String daddr) throws PacketParseException {
        Packet pkt = new Packet();
        pkt.version = version;
        pkt.protocol = protocol;
        pkt.saddr = saddr;
        pkt.daddr = daddr;
        pkt.uid = -1;
        pkt.flags = "";
        pkt.data = "";

        int remaining = raw.length - payloadOffset;

        if (protocol == PROTO_ICMP || protocol == PROTO_ICMPV6) {
            if (remaining < ICMP_MINLEN) {
                throw new PacketParseException("ICMP too short: remaining " + remaining);
            }
            int type = raw[payloadOffset] & 0xFF;
            int code = raw[payloadOffset + 1] & 0xFF;
            // ICMP ID is at offset 4-5 in the ICMP header
            int id = ((raw[payloadOffset + 4] & 0xFF) << 8) | (raw[payloadOffset + 5] & 0xFF);
            pkt.sport = id;
            pkt.dport = id;
            pkt.data = "type " + type + "/" + code;

        } else if (protocol == PROTO_UDP) {
            if (remaining < UDP_HEADER_SIZE) {
                throw new PacketParseException("UDP too short: remaining " + remaining);
            }
            pkt.sport = ((raw[payloadOffset] & 0xFF) << 8) | (raw[payloadOffset + 1] & 0xFF);
            pkt.dport = ((raw[payloadOffset + 2] & 0xFF) << 8) | (raw[payloadOffset + 3] & 0xFF);

        } else if (protocol == PROTO_TCP) {
            if (remaining < TCP_HEADER_MIN) {
                throw new PacketParseException("TCP too short: remaining " + remaining);
            }
            pkt.sport = ((raw[payloadOffset] & 0xFF) << 8) | (raw[payloadOffset + 1] & 0xFF);
            pkt.dport = ((raw[payloadOffset + 2] & 0xFF) << 8) | (raw[payloadOffset + 3] & 0xFF);

            // TCP data offset (high nibble of byte 12)
            int doff = (raw[payloadOffset + 12] & 0xF0) >> 4;
            if (doff < 5) {
                throw new PacketParseException("TCP data offset too small: " + doff);
            }

            // TCP flags (byte 13)
            int flagByte = raw[payloadOffset + 13] & 0xFF;
            StringBuilder flags = new StringBuilder();
            if ((flagByte & 0x02) != 0) flags.append('S'); // SYN
            if ((flagByte & 0x10) != 0) flags.append('A'); // ACK
            if ((flagByte & 0x08) != 0) flags.append('P'); // PSH
            if ((flagByte & 0x01) != 0) flags.append('F'); // FIN
            if ((flagByte & 0x04) != 0) flags.append('R'); // RST
            pkt.flags = flags.toString();

        } else {
            // Unknown protocol - still return packet with basic info
            pkt.sport = 0;
            pkt.dport = 0;
        }

        return pkt;
    }

    private static boolean isUpperLayer(int protocol) {
        return protocol == PROTO_TCP || protocol == PROTO_UDP
                || protocol == PROTO_ICMP || protocol == PROTO_ICMPV6;
    }

    private static boolean isLowerLayer(int protocol) {
        // Extension header next-header values
        return protocol == 0   // Hop-by-Hop
                || protocol == 43  // Routing
                || protocol == 44  // Fragment
                || protocol == 60; // Destination Options
    }

    private static String inet4ToString(byte[] addr) {
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "."
                + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
    }

    private static String inet6ToString(byte[] addr) {
        try {
            InetAddress ia = InetAddress.getByAddress(addr);
            return ia.getHostAddress();
        } catch (UnknownHostException e) {
            // Fallback: build a simple hex representation
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < addr.length; i += 2) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02x%02x", addr[i] & 0xFF, addr[i + 1] & 0xFF));
            }
            return sb.toString();
        }
    }
}
