#include <pcap.h>
#include <iostream>
#include <cstdlib>

#include <netinet/if_ether.h> // Ethernet
#include <net/if_arp.h>       // ARP
#include <netinet/ip.h>       // IP
#include <netinet/tcp.h>      // TCP
#include <netinet/udp.h>      // UDP
#include <arpa/inet.h>        // inet_ntoa
#include <pcap/sll.h>         // Linux cooked capture (SLL)
#include <map>
#include <set>
#include <string>
#include <fstream>
#include <cstring>
#include <ctime>
#include <sstream>
#include <vector>

// global vars
struct Tracker {
    int count;
    time_t start_time;
};

struct PortTracker {
    std::set<int> ports;
    time_t start_time;
    bool alerted;
};

std::map<std::string, PortTracker> port_scan_map;

// ARP Spoofing Detection — maps IP addresses to their known MAC addresses
std::map<std::string, std::string> arp_table;

//Stateful SYN Flood Detection
//tracks pending or half open connections
//SYN sent but no ACK received
//key: "SrcIP:SrcPort->DstIP:DstPort", Value: timestamp of the SYN
std::map<std::string, time_t> pending_connections;

//configured thresholds
int CURRENT_THRESHOLD = 20; //dynamic, loaded from config.json
const int STALE_SYN_THRESHOLD = 20;     // nmber of stale half-open connections to trigger alert
const int STALE_TIMEOUT_SEC = 10;       // secs before a pending SYN is considered stale
const int TIME_WINDOW_SEC = 5; // secs

// witelisted ports legitimate services to ignore in port scan detection
const std::set<int> whitelisted_ports = {80, 443, 53}; // HTTP, HTTPS, DNS

// --- Helper Functions ---
std::string get_current_timestamp() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return std::string(buf);
}

void log_alert(const std::string& type, const std::string& src_ip, const std::string& details) {
    std::ofstream log_file("logs/alerts.json", std::ios_base::app);
    if (log_file.is_open()) {
        log_file << "{ \"timestamp\": \"" << get_current_timestamp() << "\", "
                 << "\"type\": \"" << type << "\", "
                 << "\"src_ip\": \"" << src_ip << "\", "
                 << "\"details\": \"" << details << "\" }" << std::endl;
        log_file.close();
    }
}

void load_config() {
    std::ifstream config_file("config.json");
    if (config_file.is_open()) {
        std::string line;
        while (std::getline(config_file, line)) {
            // simple parsing for {"threshold": X}
            size_t pos = line.find("threshold\":");
            if (pos != std::string::npos) {
                CURRENT_THRESHOLD = std::stoi(line.substr(pos + 11));
            }
        }
    }
}

void check_port_scan(const std::string& src_ip, int dest_port) {
    load_config(); // reload settings before checking
    // skip whitelisted ports
    if (whitelisted_ports.count(dest_port)) return;

    time_t now = time(0);

    // f IP is new, initialize it
    if (port_scan_map.find(src_ip) == port_scan_map.end()) {
        port_scan_map[src_ip] = { {dest_port}, now, false };
        return;
    }

    PortTracker& tracker = port_scan_map[src_ip];

    //if within the time window, keep accumulating ports
    if (difftime(now, tracker.start_time) <= TIME_WINDOW_SEC) {
        tracker.ports.insert(dest_port);

        //only alert the FIRST time the threshold is crossed in this window
        if (!tracker.alerted && tracker.ports.size() > static_cast<size_t>(CURRENT_THRESHOLD)) {
            std::string msg = "Unique Ports: " + std::to_string(tracker.ports.size()) + 
                              " in " + std::to_string(TIME_WINDOW_SEC) + "s";
            std::cerr << "[ALERT] Potential Port Scan detected from: " << src_ip 
                      << " (" << msg << ")" << std::endl;
            
            log_alert("Port Scan", src_ip, msg);
            tracker.alerted = true;  //suppress further alerts in this window
        }
    } else {
        //time window has fully elapsed — reset everything
        tracker.ports.clear();
        tracker.ports.insert(dest_port);
        tracker.start_time = now;
        tracker.alerted = false;
    }
}

// --- ARP Spoofing Detection ---
void check_arp_spoof(const std::string& ip, const std::string& mac) {
    // Ignore broadcast, zero, and multicast addresses
    if (ip == "0.0.0.0" || ip.rfind("224.", 0) == 0 || ip == "255.255.255.255") return;

    if (arp_table.count(ip)) {
        if (arp_table[ip] != mac) {
            // The MAC for this IP changed — likely ARP spoofing
            std::string details = "MAC changed! Old: [" + arp_table[ip] + "] New: [" + mac + "]";
            std::cerr << "[ALERT] ARP Spoofing Detected for IP: " << ip << std::endl;
            std::cerr << "        " << details << std::endl;
            log_alert("ARP Spoofing", ip, details);
        }
    } else {
        std::cout << "[ARP] Learned " << ip << " -> " << mac << std::endl;
    }

    // Always update with the latest mapping
    arp_table[ip] = mac;
}

//Stateful SYN Flood Functions

// Step 2 when a SYN is seen record the pending connection
void track_syn(const std::string& src_ip, int src_port,
               const std::string& dst_ip, int dst_port) {
    std::string key = src_ip + ":" + std::to_string(src_port) + "->" +
                      dst_ip + ":" + std::to_string(dst_port);
    pending_connections[key] = time(0);
}

// Step 3 when a corresponding ACK completes the handshake remove it
void track_ack(const std::string& src_ip, int src_port,
               const std::string& dst_ip, int dst_port) {
    // The ACK goes in the reverse direction of the original SYN
    std::string key = dst_ip + ":" + std::to_string(dst_port) + "->" +
                      src_ip + ":" + std::to_string(src_port);
    pending_connections.erase(key);
}

// Step 4 check for stale half open connections meaning older than STALE_TIMEOUT_SEC
void check_stale_connections() {
    time_t now = time(0);

    // count stale connections per source IP
    std::map<std::string, int> stale_counts;
    std::vector<std::string> to_remove;

    for (auto& entry : pending_connections) {
        if (difftime(now, entry.second) > STALE_TIMEOUT_SEC) {
            // extract source IP from key "SrcIP:SrcPort->DstIP:DstPort"
            std::string src_ip = entry.first.substr(0, entry.first.find(':'));
            stale_counts[src_ip]++;
            to_remove.push_back(entry.first);
        }
    }

    // alert for IPs with many stale half-open connections
    for (auto& pair : stale_counts) {
        if (pair.second > STALE_SYN_THRESHOLD) {
            std::string msg = "Half-open connections: " + std::to_string(pair.second) +
                              " (stale > " + std::to_string(STALE_TIMEOUT_SEC) + "s)";
            std::cerr << "[ALERT] Potential SYN Flood (stateful) from: " << pair.first
                      << " (" << msg << ")" << std::endl;
            log_alert("SYN Flood", pair.first, msg);
        }
    }

    // clean up stale entries
    for (auto& key : to_remove) {
        pending_connections.erase(key);
    }
}


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // determine link layer header size based on datalink type
    pcap_t *handle = (pcap_t *)args;
    int linktype = pcap_datalink(handle);
    int link_header_len = 0;
    uint16_t ether_type = 0;

    if (linktype == DLT_EN10MB) {
        // standard ethernet 14-byte header
        link_header_len = 14;
        struct ether_header *eth_header = (struct ether_header *) packet;
        ether_type = ntohs(eth_header->ether_type);
    } else if (linktype == DLT_LINUX_SLL) {
        // linux cooked capture (16-byte header, used by "any" device)
        link_header_len = 16;
        // Protocol type is at bytes 14-15 in SLL header
        ether_type = ntohs(*(uint16_t *)(packet + 14));
    } else {
        // unsupported link type so skip
        return;
    }

    // --- ARP Detection (Ethernet only) ---
    if (ether_type == ETHERTYPE_ARP && linktype == DLT_EN10MB) {
        struct ether_arp *arp_packet = (struct ether_arp *)(packet + link_header_len);

        // Process ARP Replies and Requests
        uint16_t arp_opcode = ntohs(arp_packet->ea_hdr.ar_op);
        if (arp_opcode == ARPOP_REPLY || arp_opcode == ARPOP_REQUEST) {
            // Extract sender IP
            struct in_addr sender_ip;
            memcpy(&sender_ip, arp_packet->arp_spa, sizeof(sender_ip));
            std::string ip_str = inet_ntoa(sender_ip);

            // Extract sender MAC
            char mac_buf[18];
            snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     arp_packet->arp_sha[0], arp_packet->arp_sha[1], arp_packet->arp_sha[2],
                     arp_packet->arp_sha[3], arp_packet->arp_sha[4], arp_packet->arp_sha[5]);
            std::string mac_str(mac_buf);

            check_arp_spoof(ip_str, mac_str);
        }
        return; // ARP is not IP, nothing more to do
    }

    if (ether_type != ETHERTYPE_IP) {
        // not an IP or ARP packet so skip
        return;
    }

    // 2. IP Header
    const u_char *ip_header_start = packet + link_header_len;
    // we can use struct ip from <netinet/ip.h>
    struct ip *ip_header = (struct ip *) ip_header_start;

    std::cout << "Captured Packet Length: " << header->len << std::endl;
    std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) 
              << " -> Dest IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

    // 3. protocol (TCP/UDP)
    // IP header length is in 32-bit words, so multiply by 4 to get bytes
    int ip_header_len = ip_header->ip_hl * 4;
    
    // safely copy IP strings
    std::string src_ip_str(inet_ntoa(ip_header->ip_src));
    std::string dst_ip_str(inet_ntoa(ip_header->ip_dst));

    // filter out local/loopback traffic to reduce false positives
    if (src_ip_str == "127.0.0.1" || src_ip_str == "0.0.0.0") {
        return; // Ignore internal system chatter
    }

    if (ip_header->ip_p == IPPROTO_TCP) {
        // TCP Header follows IP Header
        const u_char *tcp_header_start = ip_header_start + ip_header_len;
        struct tcphdr *tcp_header = (struct tcphdr *) tcp_header_start;

        int src_port = ntohs(tcp_header->source);
        int dst_port = ntohs(tcp_header->dest);

        std::cout << "Protocol: TCP" << std::endl;
        std::cout << "Src Port: " << src_port 
                  << " -> Dst Port: " << dst_port << std::endl;
        std::cout << "Flags: ";
        if (tcp_header->syn) std::cout << "SYN ";
        if (tcp_header->ack) std::cout << "ACK ";
        if (tcp_header->fin) std::cout << "FIN ";
        if (tcp_header->rst) std::cout << "RST ";
        if (tcp_header->psh) std::cout << "PSH ";
        if (tcp_header->urg) std::cout << "URG ";
        std::cout << std::endl;

        //Detection Logic
        
        // 1. Port Scan Detection (track unique destination ports for source IP)
        check_port_scan(src_ip_str, dst_port);

        // 2. Stateful SYN Flood Detection
        if (tcp_header->syn && !tcp_header->ack) {
            // Pure SYN — record as pending half-open connection
            track_syn(src_ip_str, src_port, dst_ip_str, dst_port);
        } else if (tcp_header->ack) {
            // ACK — connection completed, remove from pending
            track_ack(src_ip_str, src_port, dst_ip_str, dst_port);
        }

        // Periodically check for stale half-open connections
        check_stale_connections();

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        // UDP Header follows IP Header
        const u_char *udp_header_start = ip_header_start + ip_header_len;
        struct udphdr *udp_header = (struct udphdr *) udp_header_start;

        std::cout << "Protocol: UDP" << std::endl;
        std::cout << "Src Port: " << ntohs(udp_header->source) 
                  << " -> Dst Port: " << ntohs(udp_header->dest) << std::endl;
    }

    // Print a separator
    std::cout << "--------------------------------------" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    // Step 1: find a device
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }
    
    pcap_freealldevs(alldevs);

    // Use "any" to capture on ALL interfaces (lo, wlo1, etc.)
    const char *dev = "any";
    std::cout << "Device: " << dev << std::endl;

    // Step 2: Open the device
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return 2;
    }

    std::cout << "Link-layer type: " << pcap_datalink(handle) << std::endl;

    // Step 3: Capture packets — pass handle as args for link-layer detection
    std::cout << "Starting packet capture..." << std::endl;
    pcap_loop(handle, 0, packet_handler, (u_char *)handle);

    pcap_close(handle);
    return 0;
}
