//
// Created by User on 26/09/2025.
//
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <ctime>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #define CLOSE_SOCKET close
#endif

class NetworkScanner {
public:
    struct PortResult {
        int port;
        bool isOpen;
        std::string service;
        std::string banner;
        std::string vulnerability;
        int severity; // 1=Low, 2=Medium, 3=High, 4 =Critical
    };

    struct ScanResults {
        std::string targetIP;
        std::vector<PortResult> ports;
        std::time_t scanTime;
        int totalVulnerabilities;
    };

private:
    std::map<int, std::string> commonPorts;
    std::map<std::string, std::vector<std::string>> knownVulnerabilities;

public:
    NetworkScanner() {
        initializeCommonPorts();
        initializeVulnerabilityDB();

#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
            throw std::runtime_error("Failed to initialize Winsock");
        }
#endif
    }

    ~NetworkScanner() {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    void initializeCommonPorts() {
        commonPorts[21] = "FTP";
        commonPorts[22] = "SSH";
        commonPorts[23] = "Telnet";
        commonPorts[25] = "SMTP";
        commonPorts[53] = "DNS";
        commonPorts[80] = "HTTP";
        commonPorts[110] = "POP3";
        commonPorts[135] = "RPC";
        commonPorts[139] = "NetBIOS";
        commonPorts[143] = "IMAP";
        commonPorts[443] = "HTTPS";
        commonPorts[445] = "SMB";
        commonPorts[993] = "IMAPS";
        commonPorts[995] = "POP3S";
        commonPorts[1433] = "MSSQL";
        commonPorts[1521] = "Oracle";
        commonPorts[3306] = "MySQL";
        commonPorts[3389] = "RDP";
        commonPorts[5432] = "PostgreSQL";
        commonPorts[5900] = "VNC";
    }

    void initializeVulnerabilityDB() {
        knownVulnerabilities["FTP"].push_back("Anonymous FTP access might be enabled");
        knownVulnerabilities["FTP"].push_back("Plain text authentication");

        knownVulnerabilities["Telnet"].push_back("Unencrypted protocol - credentials sent in plain text");

        knownVulnerabilities["HTTP"].push_back("Missing security headers");
        knownVulnerabilities["HTTP"].push_back("Potential directory listing");

        knownVulnerabilities["SSH"].push_back("Check for weak encryption algorithms");
        knownVulnerabilities["SSH"].push_back("Verify root login settings");

        knownVulnerabilities["RDP"].push_back("RDP exposed to internet");
        knownVulnerabilities["RDP"].push_back("Check authentication protocols");
    }

	bool isPortOpen(const std::string& ip, int port, int timeoutSeconds = 1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;

#ifdef _WIN32
        unsigned long mode = 1;
		if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
            CLOSE_SOCKET(sock);
            return false;
        }
#else
		int flags = fcntl(sock, F_GETFL, 0);









