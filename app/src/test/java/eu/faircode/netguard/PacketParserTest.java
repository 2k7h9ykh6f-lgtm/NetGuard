package eu.faircode.netguard;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.Assert.*;

/**
 * JVM unit tests for {@link PacketParser}.
 *
 * <p>Constructs raw IP packet byte arrays covering TCP, UDP, ICMP, IPv6,
 * short packets, and corrupted headers to verify the Java parser matches
 * the native C parsing logic and adds proper bounds checking.</p>
 */
public class PacketParserTest {

    // ========================================================================
    // IPv4 + TCP
    // ========================================================================

    @Test
    public void parseIPv4TcpSyn() throws Exception {
        byte[] pkt = buildIPv4Packet(
                /* protocol */ 6,
                /* srcIp */ new byte[]{10, 0, 0, 1},
                /* dstIp */ new byte[]{93, (byte) 184, (byte) 216, 34},
                /* payload */ buildTcpHeader(49152, 80, 0x02) // SYN
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals(4, p.version);
        assertEquals(6, p.protocol);
        assertEquals("10.0.0.1", p.saddr);
        assertEquals("93.184.216.34", p.daddr);
        assertEquals(49152, p.sport);
        assertEquals(80, p.dport);
        assertEquals("S", p.flags);
        assertEquals(-1, p.uid);
    }

    @Test
    public void parseIPv4TcpSynAck() throws Exception {
        byte[] pkt = buildIPv4Packet(6,
                new byte[]{(byte) 192, (byte) 168, 1, 1},
                new byte[]{10, 0, 0, 5},
                buildTcpHeader(80, 12345, 0x12) // SYN+ACK
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals("SA", p.flags);
        assertEquals(80, p.sport);
        assertEquals(12345, p.dport);
    }

    @Test
    public void parseIPv4TcpAllFlags() throws Exception {
        // SYN=0x02, ACK=0x10, PSH=0x08, FIN=0x01, RST=0x04 => all = 0x1F
        byte[] pkt = buildIPv4Packet(6,
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                buildTcpHeader(1000, 2000, 0x1F)
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals("SAPFR", p.flags);
    }

    @Test
    public void parseIPv4TcpNoFlags() throws Exception {
        byte[] pkt = buildIPv4Packet(6,
                new byte[]{1, 1, 1, 1},
                new byte[]{2, 2, 2, 2},
                buildTcpHeader(100, 200, 0x00) // no flags
        );
        Packet p = PacketParser.parse(pkt);
        assertEquals("", p.flags);
    }

    @Test
    public void parseIPv4TcpFinAck() throws Exception {
        byte[] pkt = buildIPv4Packet(6,
                new byte[]{10, 10, 10, 10},
                new byte[]{20, 20, 20, 20},
                buildTcpHeader(5000, 443, 0x11) // FIN+ACK
        );
        Packet p = PacketParser.parse(pkt);
        assertEquals("AF", p.flags);
    }

    // ========================================================================
    // IPv4 + UDP
    // ========================================================================

    @Test
    public void parseIPv4Udp() throws Exception {
        byte[] pkt = buildIPv4Packet(17,
                new byte[]{(byte) 192, (byte) 168, 0, 1},
                new byte[]{8, 8, 8, 8},
                buildUdpHeader(53421, 53)
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals(4, p.version);
        assertEquals(17, p.protocol);
        assertEquals("192.168.0.1", p.saddr);
        assertEquals("8.8.8.8", p.daddr);
        assertEquals(53421, p.sport);
        assertEquals(53, p.dport);
        assertEquals("", p.flags);
    }

    @Test
    public void parseIPv4UdpDnsPort() throws Exception {
        byte[] pkt = buildIPv4Packet(17,
                new byte[]{10, 0, 0, 100},
                new byte[]{1, 1, 1, 1},
                buildUdpHeader(60000, 53)
        );
        Packet p = PacketParser.parse(pkt);
        assertEquals(53, p.dport);
    }

    // ========================================================================
    // IPv4 + ICMP
    // ========================================================================

    @Test
    public void parseIPv4IcmpEchoRequest() throws Exception {
        // ICMP type=8 (echo request), code=0, id=0x1234
        byte[] icmp = new byte[8];
        icmp[0] = 8;  // type
        icmp[1] = 0;  // code
        // checksum at [2..3] - not validated by Java parser
        icmp[4] = 0x12; // ID high
        icmp[5] = 0x34; // ID low

        byte[] pkt = buildIPv4Packet(1,
                new byte[]{(byte) 192, (byte) 168, 1, 100},
                new byte[]{8, 8, 8, 8},
                icmp
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals(1, p.protocol);
        assertEquals(0x1234, p.sport);
        assertEquals(0x1234, p.dport);
        assertEquals("type 8/0", p.data);
    }

    @Test
    public void parseIPv4IcmpEchoReply() throws Exception {
        byte[] icmp = new byte[8];
        icmp[0] = 0;  // type = echo reply
        icmp[1] = 0;  // code
        icmp[4] = 0x00;
        icmp[5] = 0x01; // ID = 1

        byte[] pkt = buildIPv4Packet(1,
                new byte[]{8, 8, 8, 8},
                new byte[]{(byte) 192, (byte) 168, 1, 100},
                icmp
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals("type 0/0", p.data);
        assertEquals(1, p.sport);
        assertEquals(1, p.dport);
    }

    // ========================================================================
    // IPv6
    // ========================================================================

    @Test
    public void parseIPv6Tcp() throws Exception {
        byte[] tcpPayload = buildTcpHeader(8080, 443, 0x02);
        byte[] pkt = buildIPv6Packet(6,
                // src: ::1
                new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                // dst: 2001:db8::1
                new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                tcpPayload
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals(6, p.version);
        assertEquals(6, p.protocol);
        assertEquals(8080, p.sport);
        assertEquals(443, p.dport);
        assertEquals("S", p.flags);
    }

    @Test
    public void parseIPv6Udp() throws Exception {
        byte[] udpPayload = buildUdpHeader(12345, 53);
        byte[] pkt = buildIPv6Packet(17,
                new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
                new byte[]{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x88, (byte) 0x88},
                udpPayload
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals(6, p.version);
        assertEquals(17, p.protocol);
        assertEquals(12345, p.sport);
        assertEquals(53, p.dport);
    }

    // ========================================================================
    // Unknown / unsupported protocols
    // ========================================================================

    @Test
    public void parseIPv4UnknownProtocol() throws Exception {
        // Protocol 47 = GRE
        byte[] payload = new byte[]{0, 0, 0, 0};
        byte[] pkt = buildIPv4Packet(47,
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                payload
        );
        Packet p = PacketParser.parse(pkt);

        assertEquals(47, p.protocol);
        assertEquals(0, p.sport);
        assertEquals(0, p.dport);
        assertEquals("", p.flags);
    }

    @Test
    public void parseIPv4EspProtocol() throws Exception {
        // Protocol 50 = ESP
        byte[] payload = new byte[]{1, 2, 3, 4};
        byte[] pkt = buildIPv4Packet(50,
                new byte[]{10, 0, 0, 1},
                new byte[]{10, 0, 0, 2},
                payload
        );
        Packet p = PacketParser.parse(pkt);
        assertEquals(50, p.protocol);
    }

    // ========================================================================
    // Short / truncated packets
    // ========================================================================

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseEmptyPacket() throws Exception {
        PacketParser.parse(new byte[0]);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseNullPacket() throws Exception {
        PacketParser.parse(null);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseIPv4TooShort() throws Exception {
        // Version=4 but only 10 bytes (need at least 20)
        byte[] pkt = new byte[10];
        pkt[0] = 0x45; // version=4, IHL=5
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseIPv6TooShort() throws Exception {
        // Version=6 but only 20 bytes (need at least 40)
        byte[] pkt = new byte[20];
        pkt[0] = 0x60; // version=6
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseTcpPayloadTooShort() throws Exception {
        // Valid IPv4 header but only 4 bytes of TCP payload (need 20)
        byte[] tcpShort = new byte[]{0, 80, 0, (byte) 0xBB}; // just 4 bytes (dst port fragment)
        byte[] pkt = buildIPv4Packet(6,
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                tcpShort
        );
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseUdpPayloadTooShort() throws Exception {
        // Valid IPv4 header but only 4 bytes of UDP payload (need 8)
        byte[] udpShort = new byte[]{0, 53, 0, 53};
        byte[] pkt = buildIPv4Packet(17,
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                udpShort
        );
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseIcmpPayloadTooShort() throws Exception {
        // Only 4 bytes of ICMP (need 8)
        byte[] icmpShort = new byte[]{8, 0, 0, 0};
        byte[] pkt = buildIPv4Packet(1,
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                icmpShort
        );
        PacketParser.parse(pkt);
    }

    // ========================================================================
    // Corrupted / malicious headers
    // ========================================================================

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseIhlTooSmall() throws Exception {
        // IHL = 3 (12 bytes) which is less than minimum 20 bytes
        byte[] pkt = new byte[20];
        pkt[0] = 0x43; // version=4, IHL=3
        pkt[2] = 0;
        pkt[3] = 20; // tot_len = 20
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseIhlExceedsPacketLength() throws Exception {
        // IHL = 15 (60 bytes header) but packet is only 20 bytes
        byte[] pkt = new byte[20];
        pkt[0] = 0x4F; // version=4, IHL=15
        pkt[2] = 0;
        pkt[3] = 20; // tot_len = 20
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseTotLenMismatch() throws Exception {
        // Build a valid packet, then corrupt tot_len
        byte[] pkt = buildIPv4Packet(17,
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                buildUdpHeader(1234, 5678)
        );
        // Corrupt total length field to be different from actual length
        pkt[2] = 0;
        pkt[3] = (byte) (pkt.length + 10); // claim 10 more bytes
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseIpFragment() throws Exception {
        // Build a packet with the MF (More Fragments) flag set
        byte[] payload = buildUdpHeader(1234, 5678);
        int totalLen = 20 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45); // version=4, IHL=5
        buf.put((byte) 0x00); // DSCP/ECN
        buf.putShort((short) totalLen); // tot_len
        buf.putShort((short) 0x1234); // identification
        buf.putShort((short) 0x2000); // flags: MF=1, offset=0
        buf.put((byte) 64); // TTL
        buf.put((byte) 17); // protocol = UDP
        buf.putShort((short) 0); // checksum (not validated)
        buf.put(new byte[]{1, 2, 3, 4}); // src
        buf.put(new byte[]{5, 6, 7, 8}); // dst
        buf.put(payload);
        PacketParser.parse(buf.array());
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseTcpDataOffsetTooSmall() throws Exception {
        // TCP doff = 3 (< 5 minimum)
        byte[] tcp = new byte[20];
        tcp[0] = 0; tcp[1] = (byte) 80; // src port = 80
        tcp[2] = 0; tcp[3] = (byte) 443; // dst port = 443
        tcp[12] = 0x30; // doff = 3 (in high nibble)
        byte[] pkt = buildIPv4Packet(6,
                new byte[]{1, 2, 3, 4},
                new byte[]{5, 6, 7, 8},
                tcp
        );
        PacketParser.parse(pkt);
    }

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseUnknownVersion() throws Exception {
        byte[] pkt = new byte[40];
        pkt[0] = 0x70; // version = 7
        PacketParser.parse(pkt);
    }

    // ========================================================================
    // IPv4 with IP options (IHL > 5)
    // ========================================================================

    @Test
    public void parseIPv4WithOptions() throws Exception {
        // IHL = 6 means 24 bytes header (4 bytes of options)
        byte[] options = new byte[]{0x01, 0x01, 0x01, 0x01}; // NOP padding
        byte[] tcpPayload = buildTcpHeader(1234, 80, 0x02);
        int headerLen = 24;
        int totalLen = headerLen + tcpPayload.length;

        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x46); // version=4, IHL=6
        buf.put((byte) 0x00);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0); // id
        buf.putShort((short) 0); // flags/frag
        buf.put((byte) 64); // TTL
        buf.put((byte) 6); // TCP
        buf.putShort((short) 0); // checksum
        buf.put(new byte[]{10, 0, 0, 1}); // src
        buf.put(new byte[]{10, 0, 0, 2}); // dst
        buf.put(options); // IP options
        buf.put(tcpPayload);

        Packet p = PacketParser.parse(buf.array());
        assertEquals(6, p.protocol);
        assertEquals(1234, p.sport);
        assertEquals(80, p.dport);
        assertEquals("S", p.flags);
    }

    // ========================================================================
    // Single-byte packet
    // ========================================================================

    @Test(expected = PacketParser.PacketParseException.class)
    public void parseSingleByte() throws Exception {
        PacketParser.parse(new byte[]{0x45});
    }

    // ========================================================================
    // Helper methods to build raw packets
    // ========================================================================

    /**
     * Build a minimal IPv4 packet with the given protocol and payload.
     */
    private static byte[] buildIPv4Packet(int protocol, byte[] srcIp, byte[] dstIp,
                                           byte[] payload) {
        int headerLen = 20;
        int totalLen = headerLen + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);

        buf.put((byte) 0x45); // version=4, IHL=5
        buf.put((byte) 0x00); // DSCP/ECN
        buf.putShort((short) totalLen);
        buf.putShort((short) 0x0000); // identification
        buf.putShort((short) 0x0000); // flags + fragment offset (no fragmentation)
        buf.put((byte) 64); // TTL
        buf.put((byte) protocol);
        buf.putShort((short) 0); // header checksum (not validated by parser)
        buf.put(srcIp);
        buf.put(dstIp);
        buf.put(payload);

        return buf.array();
    }

    /**
     * Build a minimal IPv6 packet with the given next-header and payload.
     */
    private static byte[] buildIPv6Packet(int nextHeader, byte[] srcIp6, byte[] dstIp6,
                                           byte[] payload) {
        int totalLen = 40 + payload.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);

        // Version (4 bits) = 6, Traffic Class (8 bits) = 0, Flow Label (20 bits) = 0
        buf.putInt(0x60000000);
        buf.putShort((short) payload.length); // payload length
        buf.put((byte) nextHeader);
        buf.put((byte) 64); // hop limit
        buf.put(srcIp6);
        buf.put(dstIp6);
        buf.put(payload);

        return buf.array();
    }

    /**
     * Build a 20-byte TCP header with the given ports and flags byte.
     */
    private static byte[] buildTcpHeader(int srcPort, int dstPort, int flagsByte) {
        ByteBuffer buf = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putInt(0); // sequence number
        buf.putInt(0); // ack number
        buf.put((byte) 0x50); // data offset = 5 (20 bytes), reserved = 0
        buf.put((byte) flagsByte);
        buf.putShort((short) 8192); // window size
        buf.putShort((short) 0); // checksum
        buf.putShort((short) 0); // urgent pointer
        return buf.array();
    }

    /**
     * Build an 8-byte UDP header with the given ports.
     */
    private static byte[] buildUdpHeader(int srcPort, int dstPort) {
        ByteBuffer buf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) 8); // length = header only
        buf.putShort((short) 0); // checksum
        return buf.array();
    }
}
