# Cybersecurity
My repository on GitHub about cybersecurity
Local ip : 192.1*8.*.*/24 
->>>inet[ipv4 address for a local ip ]
--------------------------------------------
perform SYN scan on nmap 

Results ->>>  22 / tcp 
             443 / https
             445 / microsoft-ds
  -------------------------------------------
 Open ports ->>
         443 / https -- open 
         
 ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------        
         
         Analyze with wireshark -- 
         
Frame 20: 1399 bytes on wire (11192 bits), 1399 bytes captured (11192 bits) on interface wlan0, id 0
Ethernet II, Src: NokiaSolutio_75:a4:50 (a4:fc:a1:75:a4:50), Dst: Intel_04:68:a7 (c8:5e:a9:04:68:a7)
    Destination: Intel_04:68:a7 (c8:5e:a9:04:68:a7)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Source: NokiaSolutio_75:a4:50 (a4:fc:a1:75:a4:50)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: IPv6 (0x86dd)
    [Stream index: 0]
Internet Protocol Version 6, Src: 2404:6800:4007:832::2003, Dst: 2401:4900:882a:2c23:fe32:8186:42dc:77da
    0110 .... = Version: 6
    .... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00 (DSCP: CS0, ECN: Not-ECT)
        .... 0000 00.. .... .... .... .... .... = Differentiated Services Codepoint: Default (0)
        .... .... ..00 .... .... .... .... .... = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    .... 0000 0000 0000 0000 0000 = Flow Label: 0x00000
    Payload Length: 1345
    Next Header: UDP (17)
    Hop Limit: 58
    Source Address: 2404:6800:4007:832::2003
        [Address Space: Global Unicast]
    Destination Address: 2401:4900:882a:2c23:fe32:8186:42dc:77da
        [Address Space: Global Unicast]
    [Stream index: 2]
User Datagram Protocol, Src Port: 443, Dst Port: 38805
    Source Port: 443
    Destination Port: 38805
    Length: 1345
    Checksum: 0x9864 [unverified]
    [Checksum Status: Unverified]
    [Stream index: 0]
    [Stream Packet Number: 4]
    [Timestamps]
        [Time since first frame: 0.103838427 seconds]
        [Time since previous frame: 0.023514320 seconds]
    UDP payload (1337 bytes)
QUIC IETF
    QUIC Connection information
        [Connection Number: 0]
    [Packet Length: 1337]
    1... .... = Header Form: Long Header (1)
    .1.. .... = Fixed Bit: True
    ..10 .... = Packet Type: Handshake (2)
    Version: 1 (0x00000001)
    Destination Connection ID Length: 3
    Destination Connection ID: bea317
    Source Connection ID Length: 8
    Source Connection ID: e4c0ead56efc7a8f
    Length: 1317
    [Expert Info (Warning/Decryption): Failed to create decryption context: Secrets are not available]
        [Failed to create decryption context: Secrets are not available]
        [Severity level: Warning]
        [Group: Decryption]
    Remaining Payload […]: e3e93e7a802c7d3822037b332fe0433b6d207eefe27bc7f260c68697a354a02537d5780ddcc1f4814b5fa50dccb4413b5e71957066a722d25cb04a6256d3666bc5dbc10a56d965eabb1723740fe3d76ed5831556d66f2310b777ebaa1d654e4cc9ba99702e2db5dd127201
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Research common services running on those ports->>>>>>>>
.

20/21 (TCP) — FTP — File Transfer Protocol, often sends credentials in cleartext. — HIGH if exposed. 

22 (TCP) — SSH — Secure remote shell; often used for admin access. — MEDIUM-HIGH (exposed SSH attracts brute force). 
23 (TCP) — Telnet — Legacy remote shell, plaintext. 

25 (TCP) — SMTP — Mail transfer; can be abused for open relays. 

53 (UDP/TCP) — DNS — Name resolution; recursion or reflection abuse is risky. — MEDIUM-HIGH (if misconfigured). 

67/68 (UDP) — DHCP — IP address assignment (usually local-only). — MEDIUM (local trust issues). 

80 (TCP) — HTTP — Web server (unencrypted). — MEDIUM (depends on web app security). 

110 (TCP) — POP3 — Mail retrieval, often plaintext.

123 (UDP) — NTP — Time sync; can be used for amplification attacks. 

143 (TCP) — IMAP — Email retrieval (often requires TLS). 

161/162 (UDP) — SNMP — Device management; default community strings are sensitive. 

389 (TCP/UDP) — LDAP — Directory services (auth/config); anonymous binds can leak data. 

443 (TCP) — HTTPS — Encrypted web; risk tied to app/TLS config. — LOW-MEDIUM (depends on app & certs). 

445 (TCP) — SMB / Microsoft-DS — File sharing and Windows services; high-impact when exposed. 

3306 (TCP) — MySQL / MariaDB — Database server; should not be public. 

5432 (TCP) — PostgreSQL — Database server; same concerns as MySQL. 

3389 (TCP) — RDP — Windows remote desktop; frequent target for RCE/credential theft. 

5900 (TCP) — VNC — Remote desktop; often lacks encryption. 

6379 (TCP) — Redis — In-memory DB; default no-auth is dangerous.

8080 (TCP) — HTTP-alt / Web apps — Alternative HTTP port; same web risks as 80. 

1723 (TCP) — PPTP VPN — Old VPN protocol with known weaknesses.

69 (UDP) — TFTP — Trivial file transfer.

5060/5061 (UDP/TCP) — SIP / VoIP — Telephony; can leak call metadata or be abused. 

1194 (UDP/TCP) — OpenVPN — VPN (if misconfigured, risky). 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Identify potential security risks from open ports ->>>>>>>>>>>>>



22 (SSH) — brute force, stolen keys, weak configs → remote shell.

80/443 (HTTP/HTTPS) — web app vulnerabilities (RCE, SQLi, XSS), sensitive endpoints.

445 (SMB) — remote code execution (e.g., EternalBlue-style), data exfiltration via shares.

3389 (RDP) — credential theft, ransomware initial access.

3306 / 5432 (MySQL / PostgreSQL) — DB dumps, SQL injection escalation if apps connect insecurely.

6379 (Redis) — unauthenticated access → arbitrary data write, remote command injection via persistence misconfig.

53 (DNS) — cache poisoning, reflection/amplification DDoS.

123 (NTP) — amplification DDoS (if misconfigured).

161/162 (SNMP) — default community strings leak device configs



    
