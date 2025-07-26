# Digital Bug

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/platform-ESP8266-blue.svg)
![Status](https://img.shields.io/badge/status-in%20development-orange.svg)

A multi-mode Wi-Fi security and analysis tool for the ESP8266. Digital Bug can operate as an interactive, web-controlled scanner or as an autonomous, "fire-and-forget" passive logger.

---

## ⚠️ Disclaimer

This tool is for educational and professional testing purposes on networks you own or have explicit permission to test. Using this tool on any other network is "illegal" and "unethical". The user assumes all liability for their actions.

---

## Features

* Dual-Mode Operation:
    * Interactive Mode: Control the tool via a clean web interface hosted on the ESP8266 itself.
    * Autonomous Mode: Power it on and let it passively log all network activity to its internal memory.
* Wi-Fi Scanner: Discovers all nearby Access Points and client devices.
* Network Analysis: Identifies client/AP relationships and sniffs for probe requests to reveal hidden networks.
* Deauthentication Attack: A targeted DoS attack to test network resilience.

## Project structure
```js
Digital-Bug/
├── .gitignore          # Ignores build files and sensitive data
├── LICENSE             # Your chosen license file (e.g., MIT)
├── README.md           # The file we just designed
│
├── digitalbug.ino    # The main Arduino sketch file
│
├── data/               # For the web interface files
│   ├── index.html
│   ├── style.css
│   └── script.js
│
└── docs/               # For documentation and images
    └── web_ui_screenshot.png
```

## Getting Started

### Prerequisites

* **An ESP8266-based board** (e.g., NodeMCU, Wemos D1 Mini)  
  [Buy NodeMCU (ESP8266) on Amazon](https://www.amazon.in/dp/B0829Z1W6Y)
* Arduino IDE with the ESP8266 board manager installed.
* Required Arduino Libraries (list to be added).

### Installation

1.  Clone the repository: 
```git
git clone https://github.com/kn9annihilator/Digital-Bug/
```
2.  Open the `.ino` file in the Arduino IDE.
3.  Install the required libraries.
4.  Upload the code to your ESP8266.

---

##  Usage

### Interactive Mode

1.  Power on the ESP8266.
2.  Connect to the Wi-Fi network named **"Digitl Bug"** with the password **"deauther"**.
3.  Open your web browser and navigate to 
```html
http://192.168.4.1
```
4.  Use the web interface to scan, analyze, and test.

### Autonomous Mode

1.  (This mode is triggered by a specific condition, e.g., if a certain pin is HIGH on boot - TBD).
2.  Power on the ESP8266 with any USB power source. It will begin logging automatically.
3.  To retrieve data, power it off and connect it to a computer to download the log files.




##  Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

1.  Fork the Project
2.  Create your Feature Branch 
```git
git checkout -b feature/AmazingFeature
```
3.  Commit your Changes 
```git
git commit -m 'Add some AmazingFeature
```
4.  Push to the Branch 
```git
git push origin feature/AmazingFeature
```
5.  Open a Pull Request


##  Connect with Me
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/krishnanarula/)

