#include "marauder_advanced.h"

#include "core/display.h"
#include "core/main_menu.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "modules/wifi/wifi_atks.h"
#include "modules/wifi/sniffer.h"
#include "modules/wifi/karma_attack.h"
#include "modules/wifi/evil_portal.h"
#include <globals.h>

MarauderAdvanced marauderAdv;

// Rickroll SSIDs
const char* RICKROLL_SSIDS[] = {
    "Never Gonna Give You Up",
    "Never Gonna Let You Down",
    "Never Gonna Run Around",
    "Never Gonna Make You Cry",
    "Never Gonna Say Goodbye",
    "Never Gonna Tell a Lie",
    "And Hurt You"
};
const int RICKROLL_SSID_COUNT = sizeof(RICKROLL_SSIDS) / sizeof(RICKROLL_SSIDS[0]);

MarauderAdvanced::MarauderAdvanced()
    : _initialized(false), _attack_running(false), _scan_running(false), _channel_hopping(false),
      _current_channel(1), _current_attack(MARAUDER_ATK_NONE), _current_scan(MARAUDER_SCAN_AP),
      _pmkid_count(0), _handshake_captured(false), _handshake_len(0), _has_target(false),
      _beacon_ssids(nullptr), _beacon_ssid_count(0), _last_beacon(0), _last_deauth(0), _last_hop(0) {
    memset(&_stats, 0, sizeof(_stats));
}

MarauderAdvanced::~MarauderAdvanced() {
    end();
}

bool MarauderAdvanced::begin() {
    if (_initialized) return true;
    WiFi.mode(WIFI_MODE_STA);
    _initialized = true;
    _stats.start_time = millis();
    return true;
}

void MarauderAdvanced::end() {
    stopScan();
    stopDeauthAttack();
    stopBeaconSpam();
    stopPMKIDCapture();
    stopHandshakeCapture();
}

void MarauderAdvanced::startAPScan(uint8_t channel) {
    _current_scan = MARAUDER_SCAN_AP;
    _scan_running = true;
    if (channel) setChannel(channel);
}

void MarauderAdvanced::startClientScan() { _current_scan = MARAUDER_SCAN_STATION; _scan_running = true; }
void MarauderAdvanced::startProbeScan() { _current_scan = MARAUDER_SCAN_PROBE; _scan_running = true; }
void MarauderAdvanced::stopScan() { _scan_running = false; }

void MarauderAdvanced::startDeauthAttack(bool broadcast) {
    _current_attack = broadcast ? MARAUDER_ATK_DEAUTH_BROADCAST : MARAUDER_ATK_DEAUTH_TARGET;
    _attack_running = true;
}

void MarauderAdvanced::startDeauthTarget(uint8_t* ap_bssid, uint8_t* client_mac) {
    (void)ap_bssid; (void)client_mac;
    _current_attack = MARAUDER_ATK_DEAUTH_TARGET;
    _attack_running = true;
}

void MarauderAdvanced::stopDeauthAttack() { _attack_running = false; _current_attack = MARAUDER_ATK_NONE; }

void MarauderAdvanced::startBeaconSpam(const char** ssids, int count) {
    _beacon_ssids = ssids;
    _beacon_ssid_count = count;
    _current_attack = MARAUDER_ATK_BEACON_SPAM;
    _attack_running = true;
}
void MarauderAdvanced::startRickrollBeacons() { startBeaconSpam(RICKROLL_SSIDS, RICKROLL_SSID_COUNT); }
void MarauderAdvanced::startRandomBeacons(int count) { (void)count; _current_attack = MARAUDER_ATK_BEACON_RANDOM; _attack_running = true; }
void MarauderAdvanced::startCloneBeacons() { _current_attack = MARAUDER_ATK_BEACON_CLONE; _attack_running = true; }
void MarauderAdvanced::stopBeaconSpam() { _attack_running = false; if (_current_attack >= MARAUDER_ATK_BEACON_SPAM && _current_attack <= MARAUDER_ATK_BEACON_CLONE) _current_attack = MARAUDER_ATK_NONE; }

void MarauderAdvanced::startProbeFlood() { _current_attack = MARAUDER_ATK_PROBE_FLOOD; _attack_running = true; }
void MarauderAdvanced::stopProbeFlood() { if (_current_attack == MARAUDER_ATK_PROBE_FLOOD) _current_attack = MARAUDER_ATK_NONE; _attack_running = false; }

void MarauderAdvanced::startPMKIDCapture() {
    _pmkid_count = 0;
    _current_attack = MARAUDER_ATK_PMKID_CAPTURE;
    _attack_running = true;
    // Use existing sniffer focused on handshakes/PMKID if available
    setHandshakeSniffer();
    sniffer_setup();
}

void MarauderAdvanced::stopPMKIDCapture() {
    _attack_running = false;
    if (_current_attack == MARAUDER_ATK_PMKID_CAPTURE) _current_attack = MARAUDER_ATK_NONE;
}

void MarauderAdvanced::exportPMKID(const char* filename) {
    (void)filename; // Implement file export if needed
}

void MarauderAdvanced::startHandshakeCapture(uint8_t* target_bssid) {
    _has_target = target_bssid != nullptr;
    if (_has_target) memcpy(_target_bssid, target_bssid, 6);
    _handshake_captured = false;
    _current_attack = MARAUDER_ATK_EAPOL_CAPTURE;
    _attack_running = true;
    setHandshakeSniffer();
    sniffer_setup();
}

void MarauderAdvanced::stopHandshakeCapture() {
    _attack_running = false;
    if (_current_attack == MARAUDER_ATK_EAPOL_CAPTURE) _current_attack = MARAUDER_ATK_NONE;
}

void MarauderAdvanced::exportHandshake(const char* filename) { (void)filename; }

void MarauderAdvanced::setChannel(uint8_t channel) { if (channel >= 1 && channel <= 13) { _current_channel = channel; esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE); } }
void MarauderAdvanced::enableChannelHopping(bool enable) { _channel_hopping = enable; }

void MarauderAdvanced::selectAP(int index) { if (index >= 0 && index < (int)_aps.size()) _aps[index].selected = true; }
void MarauderAdvanced::selectAllAPs() { for (auto &a : _aps) a.selected = true; }
void MarauderAdvanced::deselectAllAPs() { for (auto &a : _aps) a.selected = false; }
void MarauderAdvanced::selectClient(int index) { if (index >= 0 && index < (int)_clients.size()) _clients[index].selected = true; }
void MarauderAdvanced::clearTargets() { _aps.clear(); _clients.clear(); }

void MarauderAdvanced::generateRandomMAC(uint8_t* mac) { for (int i = 0; i < 6; i++) mac[i] = (uint8_t)random(0, 256); mac[0] &= 0xFE; mac[0] |= 0x02; }
String MarauderAdvanced::macToString(uint8_t* mac) { char b[18]; snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); return String(b); }
void MarauderAdvanced::stringToMAC(const char* str, uint8_t* mac) { unsigned int nums[6]; if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &nums[0], &nums[1], &nums[2], &nums[3], &nums[4], &nums[5]) == 6) for (int i=0;i<6;i++) mac[i] = (uint8_t)nums[i]; }

void MarauderAdvanced::wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    (void)buf; (void)type;
}

void MarauderAdvanced::buildDeauthFrame(uint8_t* frame, uint8_t* ap_mac, uint8_t* client_mac) {
    (void)frame; (void)ap_mac; (void)client_mac;
}
void MarauderAdvanced::buildBeaconFrame(uint8_t* frame, int* len, const char* ssid, uint8_t* bssid, uint8_t channel, bool wpa2) {
    (void)frame; (void)len; (void)ssid; (void)bssid; (void)channel; (void)wpa2;
}
void MarauderAdvanced::buildProbeFrame(uint8_t* frame, int* len, const char* ssid) {
    (void)frame; (void)len; (void)ssid;
}

void MarauderAdvanced::processBeacon(const uint8_t* frame, int len, int8_t rssi) { (void)frame; (void)len; (void)rssi; }
void MarauderAdvanced::processProbeRequest(const uint8_t* frame, int len, int8_t rssi) { (void)frame; (void)len; (void)rssi; }
void MarauderAdvanced::processProbeResponse(const uint8_t* frame, int len, int8_t rssi) { (void)frame; (void)len; (void)rssi; }
void MarauderAdvanced::processDataFrame(const uint8_t* frame, int len, int8_t rssi) { (void)frame; (void)len; (void)rssi; }
void MarauderAdvanced::processEAPOL(const uint8_t* frame, int len) { (void)frame; (void)len; }
void MarauderAdvanced::processPMKID(const uint8_t* frame, int len, int8_t rssi) { (void)frame; (void)len; (void)rssi; }
void MarauderAdvanced::hopChannel() { if (_channel_hopping) { uint8_t next = _current_channel + 1; if (next > 13) next = 1; setChannel(next); _last_hop = millis(); } }

// ================= UI / MENU INTEGRATION =================

static void marauder_pmkid_start() {
    drawMainBorderWithTitle("PMKID Capture");
    marauderAdv.begin();
    marauderAdv.startPMKIDCapture();
    padprintln("Capturing PMKIDs / Handshakes...");
    padprintln("Press ESC to stop.");
    while (true) {
        if (check(EscPress)) break;
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
    marauderAdv.stopPMKIDCapture();
}

static void marauder_rickroll_start() {
    drawMainBorderWithTitle("Rickroll Beacons");
    marauderAdv.begin();
    marauderAdv.startRickrollBeacons();
    padprintln("Broadcasting themed SSIDs...");
    padprintln("Press ESC to stop.");
    while (true) { if (check(EscPress)) break; vTaskDelay(50 / portTICK_PERIOD_MS); }
    marauderAdv.stopBeaconSpam();
}

static void marauder_deauthflood_start() { deauthFloodAttack(); }
static void marauder_beaconspam_start() { beaconAttack(); }

void marauderAdvancedMenu() {
    options.clear();
    options.push_back({"Target Atks", [](){ wifi_atk_menu(); }});
    options.push_back({"Beacon Spam", [](){ marauder_beaconspam_start(); }});
    options.push_back({"Rickroll Beacons", [](){ marauder_rickroll_start(); }});
    options.push_back({"Deauth Flood", [](){ marauder_deauthflood_start(); }});
    options.push_back({"Probe Sniffer (Karma)", [](){ karma_setup(); }});
    options.push_back({"Raw Sniffer", [](){ sniffer_setup(); }});
    options.push_back({"PMKID/Handshake Capture", [](){ marauder_pmkid_start(); }});
    options.push_back({"Evil Twin Portal", [](){ EvilPortal(); }});
    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_SUBMENU, "Marauder+/Ghost");
}

void marauderPMKIDMenu() { marauder_pmkid_start(); }
void marauderBeaconMenu() { marauder_beaconspam_start(); }
void marauderDeauthMenu() { marauder_deauthflood_start(); }
void marauderScanMenu() { sniffer_setup(); }
