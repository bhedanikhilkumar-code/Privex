package com.privateprotection.mobile.shield;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 1035 UDP DNS packet parser and synthetic response synthesizer.
 * Operates purely in volatile memory. No disk persistence, no cloud transmission.
 *
 * Designed specifically for Android VpnService TUN interface DNS intercept.
 * Supports standard DNS query extraction (QNAME, QTYPE, QCLASS) and synthesis
 * of NXDOMAIN (RCODE 3) or Refused (RCODE 5) responses.
 */
public final class DnsPacketParser {

    private static final int DNS_PORT = 53;
    private static final int IP_HEADER_MIN_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;
    private static final int DNS_HEADER_LEN = 12;

    public static final int TYPE_A = 1;
    public static final int TYPE_AAAA = 28;
    public static final int CLASS_IN = 1;

    public static final int RCODE_NOERROR = 0;
    public static final int RCODE_NXDOMAIN = 3;
    public static final int RCODE_REFUSED = 5;

    public static final class DnsQuery {
        public final int transactionId;
        public final String qname;
        public final int qtype;
        public final int qclass;
        public final boolean isStandardQuery;

        public DnsQuery(int transactionId, String qname, int qtype, int qclass, boolean isStandardQuery) {
            this.transactionId = transactionId;
            this.qname = qname;
            this.qtype = qtype;
            this.qclass = qclass;
            this.isStandardQuery = isStandardQuery;
        }
    }

    public static final class ParsedIpUdpPacket {
        public final byte[] rawPacket;
        public final int ipVersion;
        public final int ipHeaderLen;
        public final byte[] srcIp;
        public final byte[] dstIp;
        public final int srcPort;
        public final int dstPort;
        public final int udpPayloadOffset;
        public final int udpPayloadLen;
        public final DnsQuery dnsQuery;

        public ParsedIpUdpPacket(byte[] rawPacket, int ipVersion, int ipHeaderLen,
                               byte[] srcIp, byte[] dstIp, int srcPort, int dstPort,
                               int udpPayloadOffset, int udpPayloadLen, DnsQuery dnsQuery) {
            this.rawPacket = rawPacket;
            this.ipVersion = ipVersion;
            this.ipHeaderLen = ipHeaderLen;
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.udpPayloadOffset = udpPayloadOffset;
            this.udpPayloadLen = udpPayloadLen;
            this.dnsQuery = dnsQuery;
        }
    }

    /**
     * Parse an IPv4 or IPv6 packet carrying UDP DNS query payload.
     * Returns null if not a valid IPv4/UDP or IPv6/UDP DNS packet.
     */
    public static ParsedIpUdpPacket parseIpUdpDnsPacket(byte[] packet, int length) {
        if (packet == null || length < IP_HEADER_MIN_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN) {
            return null;
        }

        int ipVersion = (packet[0] >> 4) & 0x0F;
        int ipHeaderLen;
        int protocol;
        byte[] srcIp;
        byte[] dstIp;

        if (ipVersion == 4) {
            ipHeaderLen = (packet[0] & 0x0F) * 4;
            if (length < ipHeaderLen + UDP_HEADER_LEN + DNS_HEADER_LEN) {
                return null;
            }
            protocol = packet[9] & 0xFF;
            if (protocol != 17) { // 17 is UDP
                return null;
            }
            srcIp = new byte[4];
            dstIp = new byte[4];
            System.arraycopy(packet, 12, srcIp, 0, 4);
            System.arraycopy(packet, 16, dstIp, 0, 4);
        } else if (ipVersion == 6) {
            ipHeaderLen = 40;
            if (length < ipHeaderLen + UDP_HEADER_LEN + DNS_HEADER_LEN) {
                return null;
            }
            protocol = packet[6] & 0xFF;
            if (protocol != 17) { // UDP
                return null;
            }
            srcIp = new byte[16];
            dstIp = new byte[16];
            System.arraycopy(packet, 8, srcIp, 0, 16);
            System.arraycopy(packet, 24, dstIp, 0, 16);
        } else {
            return null;
        }

        int udpOffset = ipHeaderLen;
        int srcPort = ((packet[udpOffset] & 0xFF) << 8) | (packet[udpOffset + 1] & 0xFF);
        int dstPort = ((packet[udpOffset + 2] & 0xFF) << 8) | (packet[udpOffset + 3] & 0xFF);
        int udpLen = ((packet[udpOffset + 4] & 0xFF) << 8) | (packet[udpOffset + 5] & 0xFF);

        if (dstPort != DNS_PORT && srcPort != DNS_PORT) {
            return null;
        }

        int dnsOffset = udpOffset + UDP_HEADER_LEN;
        int dnsLen = udpLen - UDP_HEADER_LEN;
        if (dnsLen < DNS_HEADER_LEN || dnsOffset + dnsLen > length) {
            return null;
        }

        DnsQuery query = parseDnsQuery(packet, dnsOffset, dnsLen);
        if (query == null) {
            return null;
        }

        return new ParsedIpUdpPacket(packet, ipVersion, ipHeaderLen, srcIp, dstIp,
                srcPort, dstPort, dnsOffset, dnsLen, query);
    }

    /**
     * Parses raw DNS message bytes to extract question name and type.
     */
    public static DnsQuery parseDnsQuery(byte[] data, int offset, int length) {
        if (data == null || length < DNS_HEADER_LEN || offset + length > data.length) {
            return null;
        }

        int transactionId = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        int flags = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        int qr = (flags >> 15) & 0x01; // 0 = query, 1 = response
        int opcode = (flags >> 11) & 0x0F;
        int qdCount = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);

        if (qr != 0 || qdCount < 1) {
            return null; // Only parsing inbound queries with at least 1 question
        }

        int cursor = offset + DNS_HEADER_LEN;
        int end = offset + length;

        // Parse QNAME
        StringBuilder qnameBuilder = new StringBuilder();
        int labelLengthTotal = 0;
        int maxHops = 128; // Protect against cyclic pointer attacks

        while (cursor < end && maxHops-- > 0) {
            int len = data[cursor++] & 0xFF;
            if (len == 0) {
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                // Compression pointer in query (rare in QNAME, but handle safely)
                if (cursor >= end) return null;
                int pointerOffset = ((len & 0x3F) << 8) | (data[cursor++] & 0xFF);
                if (pointerOffset >= offset + length) return null;
                // For safety in simple queries, stop here if compressed
                break;
            }
            if (len > 63 || cursor + len > end) {
                return null;
            }
            if (qnameBuilder.length() > 0) {
                qnameBuilder.append('.');
            }
            for (int i = 0; i < len; i++) {
                char c = (char) (data[cursor++] & 0xFF);
                qnameBuilder.append(c);
            }
            labelLengthTotal += len;
            if (labelLengthTotal > 255) {
                return null; // RFC 1035 limit
            }
        }

        if (cursor + 4 > end) {
            return null;
        }

        int qtype = ((data[cursor++] & 0xFF) << 8) | (data[cursor++] & 0xFF);
        int qclass = ((data[cursor++] & 0xFF) << 8) | (data[cursor++] & 0xFF);

        String qname = qnameBuilder.toString().toLowerCase().trim();
        return new DnsQuery(transactionId, qname, qtype, qclass, opcode == 0);
    }

    /**
     * Builds a synthetic IPv4 UDP DNS response packet (NXDOMAIN or Refused).
     * Swaps source and destination IP and ports, recalculates IP/UDP headers and checksums.
     */
    public static byte[] buildSyntheticNxdomainResponse(ParsedIpUdpPacket req, int rcode) {
        if (req == null || req.ipVersion != 4) {
            // Only synthesizing IPv4 responses for local 10.0.0.1 tunnel
            return null;
        }

        int dnsHeaderFlags = 0x8180 | (rcode & 0x0F); // QR=1, RD=1, RA=1, RCODE
        if (rcode == RCODE_NXDOMAIN) {
            dnsHeaderFlags = 0x8183; // Standard NXDOMAIN flags
        }

        // Original Question section is mirrored back
        int questionLen = req.udpPayloadLen - DNS_HEADER_LEN;
        if (questionLen < 0 || questionLen > 512) {
            questionLen = 0;
        }

        int respDnsLen = DNS_HEADER_LEN + questionLen;
        int respUdpLen = UDP_HEADER_LEN + respDnsLen;
        int respTotalLen = IP_HEADER_MIN_LEN + respUdpLen;

        byte[] resp = new byte[respTotalLen];

        // 1. IPv4 Header (20 bytes)
        resp[0] = 0x45; // Version 4, IHL 5
        resp[1] = 0x00; // DSCP / ECN
        resp[2] = (byte) ((respTotalLen >> 8) & 0xFF);
        resp[3] = (byte) (respTotalLen & 0xFF);
        resp[4] = 0x00; // ID
        resp[5] = 0x01;
        resp[6] = 0x40; // Flags (Don't Fragment)
        resp[7] = 0x00;
        resp[8] = 0x40; // TTL (64)
        resp[9] = 17;   // Protocol 17 (UDP)
        // Checksum at 10, 11 (filled later)

        // Swap IP: source becomes original dest, dest becomes original source
        System.arraycopy(req.dstIp, 0, resp, 12, 4);
        System.arraycopy(req.srcIp, 0, resp, 16, 4);

        // IPv4 Header Checksum
        int ipChecksum = computeIpChecksum(resp, 0, IP_HEADER_MIN_LEN);
        resp[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        resp[11] = (byte) (ipChecksum & 0xFF);

        // 2. UDP Header (8 bytes)
        int udpOffset = IP_HEADER_MIN_LEN;
        resp[udpOffset] = (byte) ((req.dstPort >> 8) & 0xFF);     // Swap ports
        resp[udpOffset + 1] = (byte) (req.dstPort & 0xFF);
        resp[udpOffset + 2] = (byte) ((req.srcPort >> 8) & 0xFF);
        resp[udpOffset + 3] = (byte) (req.srcPort & 0xFF);
        resp[udpOffset + 4] = (byte) ((respUdpLen >> 8) & 0xFF);
        resp[udpOffset + 5] = (byte) (respUdpLen & 0xFF);
        resp[udpOffset + 6] = 0x00; // UDP checksum (0 is valid in IPv4 UDP)
        resp[udpOffset + 7] = 0x00;

        // 3. DNS Header (12 bytes)
        int dnsOffset = udpOffset + UDP_HEADER_LEN;
        resp[dnsOffset] = (byte) ((req.dnsQuery.transactionId >> 8) & 0xFF);
        resp[dnsOffset + 1] = (byte) (req.dnsQuery.transactionId & 0xFF);
        resp[dnsOffset + 2] = (byte) ((dnsHeaderFlags >> 8) & 0xFF);
        resp[dnsOffset + 3] = (byte) (dnsHeaderFlags & 0xFF);
        resp[dnsOffset + 4] = 0x00; // QDCOUNT: 1
        resp[dnsOffset + 5] = 0x01;
        resp[dnsOffset + 6] = 0x00; // ANCOUNT: 0
        resp[dnsOffset + 7] = 0x00;
        resp[dnsOffset + 8] = 0x00; // NSCOUNT: 0
        resp[dnsOffset + 9] = 0x00;
        resp[dnsOffset + 10] = 0x00; // ARCOUNT: 0
        resp[dnsOffset + 11] = 0x00;

        // 4. Mirror Question
        if (questionLen > 0) {
            System.arraycopy(req.rawPacket, req.udpPayloadOffset + DNS_HEADER_LEN,
                    resp, dnsOffset + DNS_HEADER_LEN, questionLen);
        }

        return resp;
    }

    private static int computeIpChecksum(byte[] buf, int offset, int length) {
        int sum = 0;
        for (int i = 0; i < length; i += 2) {
            int word = ((buf[offset + i] & 0xFF) << 8) | (buf[offset + i + 1] & 0xFF);
            sum += word;
            if ((sum & 0xFFFF0000) != 0) {
                sum = (sum & 0xFFFF) + 1;
            }
        }
        return (~sum) & 0xFFFF;
    }
}
