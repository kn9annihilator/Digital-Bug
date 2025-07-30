#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>

// --- Pin Configuration ---
#define AUTONOMOUS_MODE_PIN D3 // GPIO0

// --- Data Structures for Packet Sniffing ---
struct MacHeader {
  uint8_t frameControl[2];
  uint8_t duration[2];
  uint8_t addr1[6]; // Receiver (Destination)
  uint8_t addr2[6]; // Transmitter (Source)
  uint8_t addr3[6]; // BSSID (AP MAC)
  uint8_t sequenceControl[2];
};

// --- Global Variables ---
const char* ssid = "Digital Bug";
const char* password = "deauther";
ESP8266WebServer server(80);
bool autonomousMode = false;

// NEW: A volatile boolean flag to signal stopping a process.
// "volatile" tells the compiler that this variable can be changed by external factors
// (like a web server request) at any time, preventing aggressive optimizations.
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

    // NEW: Reset the stop flag at the beginning of a new scan.
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
    // MODIFIED: The loop now also checks the stopProcess flag.
    while(millis() - startTime < 10000 && !stopProcess) {
        // We must call server.handleClient() inside long loops.
        // This allows the server to process incoming requests, like the one for /stop.
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

// NEW: This handler is called when the /stop URL is requested.
void handleStop() {
    Serial.println("[API] Received /stop request.");
    stopProcess = true; // Set the flag to true
    server.send(200, "text/plain", "OK. Process will be stopped.");
}

void handleAttack() {
    Serial.println("[API] Received /attack request. This feature is under development.");
    server.send(200, "text/plain", "Attack feature not yet implemented.");
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
  server.on("/stop", HTTP_GET, handleStop); // NEW: Register the stop handler
  server.on("/attack", HTTP_POST, handleAttack);
  server.onNotFound(handleNotFound);

  server.begin();
  Serial.println("[OK] Web server started.");
}

void loop() {
  if (!autonomousMode) {
    // In the main loop, we only need to handle client requests.
    // The client scan loop now handles its own requests.
    server.handleClient();
  }
}
