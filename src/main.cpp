#include <pcap.h>
#include <iostream>
#include <cstdlib>

// Headers for protocol definitions
#include <netinet/if_ether.h> // Ethernet
#include <netinet/ip.h>       // IP
#include <netinet/tcp.h>      // TCP
#include <netinet/udp.h>      // UDP
#include <arpa/inet.h>        // inet_ntoa
#include <pcap/sll.h>         // Linux cooked capture (SLL)
#include <map>
#include <set>
#include <string>
#include <fstream>
#include <ctime>
#include <sstream>

// --- Detection Engine Globals ---
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
std::map<std::string, Tracker> syn_flood_map;
std::map<std::string, Tracker> syn_flood_dst_map;  // Tracks SYN floods by destination (for spoofed sources)

// Configure thresholds
int CURRENT_THRESHOLD = 20; // Dynamic, loaded from config.json
const int SYN_FLOOD_THRESHOLD = 100;    // Per-source: many SYNs from one IP
const int SYN_FLOOD_DST_THRESHOLD = 50; // Per-destination: many SYNs to one IP:port (catches --rand-source)
const int TIME_WINDOW_SEC = 5; // seconds

// Whitelisted ports — legitimate services to ignore in port scan detection
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
            // Simple parsing for {"threshold": X}
            size_t pos = line.find("threshold\":");
            if (pos != std::string::npos) {
                CURRENT_THRESHOLD = std::stoi(line.substr(pos + 11));
            }
        }
    }
}

void check_port_scan(const std::string& src_ip, int dest_port) {
    load_config(); // Reload settings before checking
    // Skip whitelisted ports
    if (whitelisted_ports.count(dest_port)) return;

    time_t now = time(0);

    // If IP is new, initialize it
    if (port_scan_map.find(src_ip) == port_scan_map.end()) {
        port_scan_map[src_ip] = { {dest_port}, now, false };
        return;
    }

    PortTracker& tracker = port_scan_map[src_ip];

    // If within the time window, keep accumulating ports
    if (difftime(now, tracker.start_time) <= TIME_WINDOW_SEC) {
        tracker.ports.insert(dest_port);

        // Only alert the FIRST time the threshold is crossed in this window
        if (!tracker.alerted && tracker.ports.size() > static_cast<size_t>(CURRENT_THRESHOLD)) {
            std::string msg = "Unique Ports: " + std::to_string(tracker.ports.size()) + 
                              " in " + std::to_string(TIME_WINDOW_SEC) + "s";
            std::cerr << "[ALERT] Potential Port Scan detected from: " << src_ip 
                      << " (" << msg << ")" << std::endl;
            
            log_alert("Port Scan", src_ip, msg);
            tracker.alerted = true;  // Suppress further alerts in this window
        }
    } else {
        // Time window has fully elapsed — reset everything
        tracker.ports.clear();
        tracker.ports.insert(dest_port);
        tracker.start_time = now;
        tracker.alerted = false;
    }
}

// Detect SYN flood from a single source IP (many SYNs from one IP)
void check_syn_flood(const std::string& src_ip) {
    time_t now = time(0);

    if (syn_flood_map.find(src_ip) == syn_flood_map.end()) {
        syn_flood_map[src_ip] = {1, now};
        return;
    }

    if (difftime(now, syn_flood_map[src_ip].start_time) <= TIME_WINDOW_SEC) {
        syn_flood_map[src_ip].count++;
        
        if (syn_flood_map[src_ip].count > SYN_FLOOD_THRESHOLD) {
            std::string msg = "Packet Count: " + std::to_string(syn_flood_map[src_ip].count) + 
                              " in " + std::to_string(TIME_WINDOW_SEC) + "s";
            std::cerr << "[ALERT] Potential SYN Flood detected from: " << src_ip 
                      << " (" << msg << ")" << std::endl;
            
            log_alert("SYN Flood", src_ip, msg);
            syn_flood_map[src_ip] = {0, now}; 
        }
    } else {
        syn_flood_map[src_ip] = {1, now};
    }
}

// Detect SYN flood targeting a destination IP:port (catches spoofed/random source IPs)
void check_syn_flood_dst(const std::string& dst_ip, int dst_port, const std::string& src_ip) {
    time_t now = time(0);
    std::string key = dst_ip + ":" + std::to_string(dst_port);

    if (syn_flood_dst_map.find(key) == syn_flood_dst_map.end()) {
        syn_flood_dst_map[key] = {1, now};
        return;
    }

    if (difftime(now, syn_flood_dst_map[key].start_time) <= TIME_WINDOW_SEC) {
        syn_flood_dst_map[key].count++;
        
        if (syn_flood_dst_map[key].count > SYN_FLOOD_DST_THRESHOLD) {
            std::string msg = "SYN Count: " + std::to_string(syn_flood_dst_map[key].count) + 
                              " to " + key + " in " + std::to_string(TIME_WINDOW_SEC) + "s";
            std::cerr << "[ALERT] Potential SYN Flood targeting: " << key 
                      << " (" << msg << ")" << std::endl;
            
            log_alert("SYN Flood", dst_ip, msg);
            syn_flood_dst_map[key] = {0, now}; 
        }
    } else {
        syn_flood_dst_map[key] = {1, now};
    }
}


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Determine link-layer header size based on datalink type
    pcap_t *handle = (pcap_t *)args;
    int linktype = pcap_datalink(handle);
    int link_header_len = 0;
    uint16_t ether_type = 0;

    if (linktype == DLT_EN10MB) {
        // Standard Ethernet (14-byte header)
        link_header_len = 14;
        struct ether_header *eth_header = (struct ether_header *) packet;
        ether_type = ntohs(eth_header->ether_type);
    } else if (linktype == DLT_LINUX_SLL) {
        // Linux cooked capture (16-byte header, used by "any" device)
        link_header_len = 16;
        // Protocol type is at bytes 14-15 in SLL header
        ether_type = ntohs(*(uint16_t *)(packet + 14));
    } else {
        // Unsupported link type, skip
        return;
    }

    if (ether_type != ETHERTYPE_IP) {
        // Not an IP packet, skip
        return;
    }

    // 2. IP Header
    const u_char *ip_header_start = packet + link_header_len;
    // We can use struct ip from <netinet/ip.h>
    struct ip *ip_header = (struct ip *) ip_header_start;

    std::cout << "Captured Packet Length: " << header->len << std::endl;
    std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) 
              << " -> Dest IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

    // 3. Protocol (TCP/UDP)
    // IP header length is in 32-bit words, so multiply by 4 to get bytes
    int ip_header_len = ip_header->ip_hl * 4;
    
    // Safely copy IP strings
    std::string src_ip_str(inet_ntoa(ip_header->ip_src));
    std::string dst_ip_str(inet_ntoa(ip_header->ip_dst));

    // Filter out local/loopback traffic to reduce false positives
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

        // --- Detection Logic ---
        
        // 1. Port Scan Detection (track unique destination ports for source IP)
        check_port_scan(src_ip_str, dst_port);

        // 2. SYN Flood Detection (SYN set, ACK not set)
        if (tcp_header->syn && !tcp_header->ack) {
            check_syn_flood(src_ip_str);                        // Per-source detection
            check_syn_flood_dst(dst_ip_str, dst_port, src_ip_str); // Per-destination detection
        }

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
    
    // Step 1: Find a device
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
