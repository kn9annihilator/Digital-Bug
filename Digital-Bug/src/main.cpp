#include <Arduino.h>
#include <ESP8266WiFi.h>

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

// Performs the Wi-Fi scan and prints the results in a formatted table
void performScan() {
  Serial.println("Scanning for Wi-Fi networks...");

  // WiFi.scanNetworks will return the number of networks found.
  int numNetworks = WiFi.scanNetworks();

  if (numNetworks == 0) {
    Serial.println("No networks found.");
    return;
  }

  Serial.printf("%d networks found:\n", numNetworks);
  // Print a header for our table.
  Serial.println("-------------------------------------------------------------------------");
  Serial.printf("| %-2s | %-17s | %-4s | %-2s | %-5s | %-6s | %-32s |\n", "No", "BSSID", "RSSI", "Ch", "Encrypt", "Hidden", "SSID");
  Serial.println("-------------------------------------------------------------------------");

  // Loop through each found network and print its details
  for (int i = 0; i < numNetworks; ++i) {
    Serial.printf("| %2d | %17s | %4d | %2d | %-5s | %-6s | %-32s |\n",
                  i + 1,
                  WiFi.BSSIDstr(i).c_str(), // MAC Address of the AP
                  WiFi.RSSI(i),             // Signal Strength
                  WiFi.channel(i),          // Wi-Fi Channel
                  getEncryptionType(WiFi.encryptionType(i)).c_str(), // Encryption Type
                  WiFi.isHidden(i) ? "Yes" : "No", // Is the network hidden?
                  WiFi.SSID(i).c_str()      // Network Name
                 );
  }
  Serial.println("-------------------------------------------------------------------------");
}

void setup() {
  Serial.begin(115200);
  Serial.println("\nDigital Bug - Wi-Fi Scanner Initialized");

  // Set WiFi to station mode and disconnect from an AP if it was previously connected
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
}

void loop() {
  performScan();
  Serial.println("\nScan will repeat in 10 seconds...");
  // Wait 10 seconds before scanning again
  delay(10000);
}