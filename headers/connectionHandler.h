#pragma once
#include <pcap.h>

#define IPV6_ADDR_LENGTH_BYTES 16
#define MAC_LENGTH_BYTES 6
#define IPV6_START_OFFSET 14

void printAvailableDevices(pcap_if_t *alldevsp);
void setSystemIpAddr(pcap_if_t *alldevsp, int chosen_device_no);
void setSystemMacAddr(pcap_if_t *alldevsp, int chosen_device_no);
void callbackFunction(unsigned char *args, const struct pcap_pkthdr* pkthdr, const unsigned char* rawData);
void createPacketFromRawData(const struct pcap_pkthdr* pkthdr, const unsigned char *rawData);
pcap_if_t *getChosenDevice(pcap_if_t *alldevsp, int chosenDeviceNo);
int getNumberOfAvailableDevices(pcap_if_t *alldevsp);
bool isIPv6Packet(const unsigned char *rawData);
bool isIcmpPacket(const unsigned char *rawData);
bool isNdpPacket(const unsigned char *rawData);
bool isPingPacket(const unsigned char *rawData);
bool isTcpPacket(const unsigned char *rawData);
bool isHttpPacket(const unsigned char *rawData, int packetLength);
bool packetIntendedForThisPeer(const unsigned char *rawData);
