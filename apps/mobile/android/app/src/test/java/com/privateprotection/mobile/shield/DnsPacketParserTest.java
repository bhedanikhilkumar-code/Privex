package com.privateprotection.mobile.shield;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import static org.junit.Assert.*;

public class DnsPacketParserTest {

    private byte[] createDnsQueryPacket(int txId, String domain, int qtype) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // IPv4 Header (20 bytes)
        dos.writeByte(0x45); // IPv4, IHL 5
        dos.writeByte(0x00);
        int totalLen = 20 + 8 + 12 + getDomainLength(domain) + 4;
        dos.writeShort(totalLen);
        dos.writeShort(0x1234);
        dos.writeShort(0x4000); // DF
        dos.writeByte(64);     // TTL
        dos.writeByte(17);     // UDP protocol
        dos.writeShort(0x0000); // Checksum dummy
        dos.write(new byte[]{10, 0, 0, 2}); // Src IP: 10.0.0.2
        dos.write(new byte[]{10, 0, 0, 1}); // Dst IP: 10.0.0.1

        // UDP Header (8 bytes)
        dos.writeShort(54321); // Src Port
        dos.writeShort(53);    // Dst Port: DNS
        dos.writeShort(8 + 12 + getDomainLength(domain) + 4);
        dos.writeShort(0x0000);

        // DNS Header (12 bytes)
        dos.writeShort(txId);
        dos.writeShort(0x0100); // Standard query, RD=1
        dos.writeShort(1);      // QDCOUNT
        dos.writeShort(0);      // ANCOUNT
        dos.writeShort(0);      // NSCOUNT
        dos.writeShort(0);      // ARCOUNT

        // QNAME
        String[] labels = domain.split("\\.");
        for (String label : labels) {
            dos.writeByte(label.length());
            dos.writeBytes(label);
        }
        dos.writeByte(0x00); // Null terminator

        // QTYPE and QCLASS
        dos.writeShort(qtype);
        dos.writeShort(1); // IN class

        return baos.toByteArray();
    }

    private int getDomainLength(String domain) {
        String[] labels = domain.split("\\.");
        int len = 1; // null byte
        for (String l : labels) {
            len += 1 + l.length();
        }
        return len;
    }

    @Test
    public void testParseValidDnsQueryPacket() throws Exception {
        byte[] packet = createDnsQueryPacket(0xABCD, "phishing-bank-login.com", DnsPacketParser.TYPE_A);
        DnsPacketParser.ParsedIpUdpPacket parsed = DnsPacketParser.parseIpUdpDnsPacket(packet, packet.length);

        assertNotNull(parsed);
        assertEquals(4, parsed.ipVersion);
        assertEquals(20, parsed.ipHeaderLen);
        assertEquals(54321, parsed.srcPort);
        assertEquals(53, parsed.dstPort);

        assertNotNull(parsed.dnsQuery);
        assertEquals(0xABCD, parsed.dnsQuery.transactionId);
        assertEquals("phishing-bank-login.com", parsed.dnsQuery.qname);
        assertEquals(DnsPacketParser.TYPE_A, parsed.dnsQuery.qtype);
        assertEquals(DnsPacketParser.CLASS_IN, parsed.dnsQuery.qclass);
        assertTrue(parsed.dnsQuery.isStandardQuery);
    }

    @Test
    public void testBuildSyntheticNxdomainResponse() throws Exception {
        byte[] packet = createDnsQueryPacket(0x7788, "malicious-crypto.top", DnsPacketParser.TYPE_A);
        DnsPacketParser.ParsedIpUdpPacket parsed = DnsPacketParser.parseIpUdpDnsPacket(packet, packet.length);
        assertNotNull(parsed);

        byte[] resp = DnsPacketParser.buildSyntheticNxdomainResponse(parsed, DnsPacketParser.RCODE_NXDOMAIN);
        assertNotNull(resp);
        assertTrue(resp.length >= 20 + 8 + 12);

        // Check response IP: Src must be 10.0.0.1, Dst must be 10.0.0.2
        assertEquals(10, resp[12]);
        assertEquals(0, resp[13]);
        assertEquals(0, resp[14]);
        assertEquals(1, resp[15]);

        assertEquals(10, resp[16]);
        assertEquals(0, resp[17]);
        assertEquals(0, resp[18]);
        assertEquals(2, resp[19]);

        // Check UDP ports swapped: Src=53, Dst=54321
        int srcPort = ((resp[20] & 0xFF) << 8) | (resp[21] & 0xFF);
        int dstPort = ((resp[22] & 0xFF) << 8) | (resp[23] & 0xFF);
        assertEquals(53, srcPort);
        assertEquals(54321, dstPort);

        // Check DNS Transaction ID and Flags (RCODE=3 NXDOMAIN)
        int txId = ((resp[28] & 0xFF) << 8) | (resp[29] & 0xFF);
        assertEquals(0x7788, txId);

        int flags = ((resp[30] & 0xFF) << 8) | (resp[31] & 0xFF);
        int rcode = flags & 0x0F;
        assertEquals(DnsPacketParser.RCODE_NXDOMAIN, rcode);
        int qr = (flags >> 15) & 0x01;
        assertEquals(1, qr); // Must be a response
    }

    @Test
    public void testMalformedAndTruncatedPackets() {
        assertNull(DnsPacketParser.parseIpUdpDnsPacket(null, 0));
        assertNull(DnsPacketParser.parseIpUdpDnsPacket(new byte[10], 10));

        // Non-UDP packet (Protocol 6 TCP)
        byte[] tcpPacket = new byte[60];
        tcpPacket[0] = 0x45;
        tcpPacket[9] = 6; // TCP
        assertNull(DnsPacketParser.parseIpUdpDnsPacket(tcpPacket, 60));
    }
}
