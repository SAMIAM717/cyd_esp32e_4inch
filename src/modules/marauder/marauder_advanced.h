/**
 * @file marauder_advanced.h
 * @brief Advanced Marauder features for Bruce firmware
 * 
 * Enhanced WiFi attack capabilities including:
 * - PMKID capture and extraction
 * - Advanced beacon spam (Rickroll, custom SSIDs)
 * - Enhanced deauth with client targeting
 * - Probe request flooding
 * - EAPOL handshake capture improvements
 */

#ifndef __MARAUDER_ADVANCED_H__
#define __MARAUDER_ADVANCED_H__

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <vector>
#include <set>

// ============== CONSTANTS ==============
#define MARAUDER_MAX_SSIDS 50
#define MARAUDER_MAX_CLIENTS 100
#define MARAUDER_BEACON_INTERVAL 100
#define MARAUDER_DEAUTH_BURST 50
#define MARAUDER_CHANNEL_HOP_INTERVAL 500
#define PMKID_CAPTURE_TIMEOUT 30000

// ============== STRUCTURES ==============

// PMKID capture data structure
struct PMKIDCapture {
    uint8_t bssid[6];
    uint8_t client_mac[6];
    uint8_t pmkid[16];
    char ssid[33];
    uint32_t timestamp;
    int8_t rssi;
    bool valid;
};

// Enhanced AP info for attacks
struct MarauderAP {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    int8_t rssi;
    uint8_t encryption;
    bool selected;
    uint32_t last_seen;
    uint16_t beacon_count;
    uint16_t data_count;
};

// Client/Station tracking
struct MarauderClient {
    uint8_t mac[6];
    uint8_t ap_bssid[6];
    int8_t rssi;
    uint32_t last_seen;
    uint16_t packet_count;
    bool selected;
};

// Beacon spam configuration
struct BeaconConfig {
    bool enabled;
    uint8_t channel;
    uint16_t count;
    uint16_t delay_ms;
    bool random_mac;
    bool wpa2_flag;
};

// Attack statistics
struct MarauderStats {
    uint32_t deauth_sent;
    uint32_t beacons_sent;
    uint32_t probes_captured;
    uint32_t pmkids_captured;
    uint32_t handshakes_captured;
    uint32_t packets_sniffed;
    uint32_t start_time;
};

// ============== ENUMS ==============

enum MarauderAttackType {
    MARAUDER_ATK_NONE = 0,
    MARAUDER_ATK_DEAUTH_BROADCAST,
    MARAUDER_ATK_DEAUTH_TARGET,
    MARAUDER_ATK_BEACON_SPAM,
    MARAUDER_ATK_BEACON_RICKROLL,
    MARAUDER_ATK_BEACON_RANDOM,
    MARAUDER_ATK_BEACON_CLONE,
    MARAUDER_ATK_PROBE_FLOOD,
    MARAUDER_ATK_PMKID_CAPTURE,
    MARAUDER_ATK_EAPOL_CAPTURE,
    MARAUDER_ATK_EVIL_TWIN
};

enum MarauderScanType {
    MARAUDER_SCAN_AP = 0,
    MARAUDER_SCAN_STATION,
    MARAUDER_SCAN_PROBE,
    MARAUDER_SCAN_DEAUTH,
    MARAUDER_SCAN_RAW
};

// ============== CLASS DEFINITION ==============

class MarauderAdvanced {
public:
    MarauderAdvanced();
    ~MarauderAdvanced();
    
    // Initialization
    bool begin();
    void end();
    
    // Scanning functions
    void startAPScan(uint8_t channel = 0);
    void startClientScan();
    void startProbeScan();
    void stopScan();
    
    // Attack functions
    void startDeauthAttack(bool broadcast = true);
    void startDeauthTarget(uint8_t* ap_bssid, uint8_t* client_mac = nullptr);
    void stopDeauthAttack();
    
    void startBeaconSpam(const char** ssids, int count);
    void startRickrollBeacons();
    void startRandomBeacons(int count);
    void startCloneBeacons();
    void stopBeaconSpam();
    
    void startProbeFlood();
    void stopProbeFlood();
    
    // PMKID capture (advanced feature)
    void startPMKIDCapture();
    void stopPMKIDCapture();
    bool hasPMKID() { return _pmkid_count > 0; }
    int getPMKIDCount() { return _pmkid_count; }
    PMKIDCapture* getPMKIDs() { return _pmkids; }
    void exportPMKID(const char* filename);
    
    // EAPOL/Handshake capture
    void startHandshakeCapture(uint8_t* target_bssid = nullptr);
    void stopHandshakeCapture();
    bool hasHandshake() { return _handshake_captured; }
    void exportHandshake(const char* filename);
    
    // Channel control
    void setChannel(uint8_t channel);
    void enableChannelHopping(bool enable);
    uint8_t getCurrentChannel() { return _current_channel; }
    
    // AP/Client management
    void selectAP(int index);
    void selectAllAPs();
    void deselectAllAPs();
    void selectClient(int index);
    void clearTargets();
    
    // Getters
    std::vector<MarauderAP>& getAPs() { return _aps; }
    std::vector<MarauderClient>& getClients() { return _clients; }
    MarauderStats& getStats() { return _stats; }
    bool isRunning() { return _attack_running; }
    MarauderAttackType getCurrentAttack() { return _current_attack; }
    
    // Utility
    void generateRandomMAC(uint8_t* mac);
    String macToString(uint8_t* mac);
    void stringToMAC(const char* str, uint8_t* mac);
    
    // Callbacks
    static void wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    
private:
    // State
    bool _initialized;
    bool _attack_running;
    bool _scan_running;
    bool _channel_hopping;
    uint8_t _current_channel;
    MarauderAttackType _current_attack;
    MarauderScanType _current_scan;
    
    // Data storage
    std::vector<MarauderAP> _aps;
    std::vector<MarauderClient> _clients;
    MarauderStats _stats;
    
    // PMKID capture
    PMKIDCapture _pmkids[10];
    int _pmkid_count;
    
    // Handshake capture
    bool _handshake_captured;
    uint8_t _handshake_data[512];
    int _handshake_len;
    uint8_t _target_bssid[6];
    bool _has_target;
    
    // Beacon spam
    BeaconConfig _beacon_config;
    const char** _beacon_ssids;
    int _beacon_ssid_count;
    
    // Timers
    uint32_t _last_beacon;
    uint32_t _last_deauth;
    uint32_t _last_hop;
    
    // Frame construction
    void buildDeauthFrame(uint8_t* frame, uint8_t* ap_mac, uint8_t* client_mac);
    void buildBeaconFrame(uint8_t* frame, int* len, const char* ssid, uint8_t* bssid, uint8_t channel, bool wpa2);
    void buildProbeFrame(uint8_t* frame, int* len, const char* ssid);
    
    // Internal processing
    void processBeacon(const uint8_t* frame, int len, int8_t rssi);
    void processProbeRequest(const uint8_t* frame, int len, int8_t rssi);
    void processProbeResponse(const uint8_t* frame, int len, int8_t rssi);
    void processDataFrame(const uint8_t* frame, int len, int8_t rssi);
    void processEAPOL(const uint8_t* frame, int len);
    void processPMKID(const uint8_t* frame, int len, int8_t rssi);
    
    // Channel hopping
    void hopChannel();
};

// ============== RICKROLL SSIDS ==============
extern const char* RICKROLL_SSIDS[];
extern const int RICKROLL_SSID_COUNT;

// ============== GLOBAL INSTANCE ==============
extern MarauderAdvanced marauderAdv;

// ============== MENU FUNCTIONS ==============
void marauderAdvancedMenu();
void marauderPMKIDMenu();
void marauderBeaconMenu();
void marauderDeauthMenu();
void marauderScanMenu();

#endif // __MARAUDER_ADVANCED_H__
