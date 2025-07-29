#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h> // For the file system

// --- Configuration ---
const char* ssid = "Digital Bug";
const char* password = "deauther";

// Create a web server object on port 80
ESP8266WebServer server(80);

// --- Helper Functions ---
// Helper function to convert encryption type number to a readable string
String getEncryptionType(uint8_t type) {
  switch (type) {
    case ENC_TYPE_NONE:
      return "OPEN";
    case ENC_TYPE_WEP:
      return "WEP";
    case ENC_TYPE_TKIP: // WPA
      return "WPA";
    case ENC_TYPE_CCMP: // WPA2
      return "WPA2";
    case ENC_TYPE_AUTO:
      return "WPA*";
    default:
      return "???";
  }
}

// --- Web Server Handlers ---

// This function is called when a client requests the root URL ("/")
void handleRoot() {
  if (LittleFS.exists("/index.html")) {
    File file = LittleFS.open("/index.html", "r");
    server.streamFile(file, "text/html");
    file.close();
  } else {
    server.send(404, "text/plain", "Error: index.html not found. Did you upload the data folder?");
  }
}

// This function handles the "/scan" request
void handleScan() {
  Serial.println("[API] Received /scan request.");
  int n = WiFi.scanNetworks();
  String html = ""; // String to build the HTML table rows

  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      // Determine RSSI color based on signal strength
      String rssi_color = "text-green-300";
      if(WiFi.RSSI(i) < -70) rssi_color = "text-yellow-400";
      if(WiFi.RSSI(i) < -80) rssi_color = "text-red-400";

      // Build the HTML for one table row
      html += "<tr class='hover:bg-green-900 hover:bg-opacity-20 transition duration-200'>";
      html += "<td class='px-4 py-3 font-medium text-green-300'>" + WiFi.SSID(i) + "</td>";
      html += "<td class='px-4 py-3 text-green-500'>" + WiFi.BSSIDstr(i) + "</td>";
      html += "<td class='px-4 py-3 " + rssi_color + " font-semibold'>" + String(WiFi.RSSI(i)) + "</td>";
      html += "<td class='px-4 py-3 text-green-500'>" + String(WiFi.channel(i)) + "</td>";
      
      // *** FIXED LINE ***
      // The original line was broken into multiple parts to avoid the C++ string literal concatenation error.
      html += "<td class='px-4 py-3'><span class='";
      html += (WiFi.encryptionType(i) == ENC_TYPE_NONE ? "text-red-400" : "text-green-300");
      html += "'>";
      html += getEncryptionType(WiFi.encryptionType(i));
      html += "</span></td>";

      html += "<td class='px-4 py-3'><input type='radio' name='target_ap' class='form-radio h-4 w-4 bg-gray-900 border-green-700'></td>";
      html += "</tr>";
    }
  } else {
      html = "<tr><td colspan='6' class='text-center px-4 py-3 text-gray-500'>No networks found.</td></tr>";
  }
  
  // Send the generated HTML back to the client
  server.send(200, "text/html", html);
  Serial.println("[API] Scan results sent.");
}


// This function is called when a client requests a page that doesn't exist
void handleNotFound() {
  server.send(404, "text/plain", "Not Found");
}

// --- Main Setup & Loop ---

void setup() {
  Serial.begin(115200);
  Serial.println("\n[INFO] Starting Digital Bug...");

  if (!LittleFS.begin()) {
    Serial.println("[ERROR] Failed to mount file system. Formatting...");
    LittleFS.format();
    if(!LittleFS.begin()){
      Serial.println("[FATAL] File system format failed. Halting.");
      return;
    }
  }
  Serial.println("[OK] File system mounted.");

  WiFi.softAP(ssid, password);
  Serial.print("[OK] Access Point '");
  Serial.print(ssid);
  Serial.println("' started.");
  Serial.print("[INFO] IP Address: ");
  Serial.println(WiFi.softAPIP());

  // Set up the web server handlers
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan); // Add the handler for our scan API
  server.onNotFound(handleNotFound);

  server.begin();
  Serial.println("[OK] Web server started.");
}

void loop() {
  server.handleClient();
}
