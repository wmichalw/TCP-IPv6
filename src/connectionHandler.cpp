#include <iostream>
#include <cstring>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <memory>
#include <sys/ioctl.h>
#include <algorithm>
#include <string>
#include "connectionHandler.h"
#include "ICMPv6Packet.h"
#include "TcpPacket.h"
#include "HttpPacket.h"

class Packet;
extern pcap_t* handle;

unsigned char systemIpAddr[IPV6_ADDR_LENGTH_BYTES];
unsigned char systemMacAddr[MAC_LENGTH_BYTES];

int getNumberOfAvailableDevices(pcap_if_t *alldevsp)
{
  int number = 0;
  for (pcap_if_t *device = alldevsp ; device != nullptr ; device = device->next)
    ++number;
  return number;
}

pcap_if_t *getChosenDevice(pcap_if_t *alldevsp, int chosenDeviceNo)
{
  pcap_if_t *device = alldevsp;

  // Start numbering devices from 1
  chosenDeviceNo -= 1;

  for (int i = 0; i < chosenDeviceNo; ++i){
    device = device->next;
  }

  return device;
}

void printAvailableDevices(pcap_if_t *alldevsp)
{
  int maxNameLen = 0;
  int deviceNo = 0;
  for (pcap_if_t *device = alldevsp ; device != nullptr ; device = device->next)
    maxNameLen = std::max(maxNameLen, static_cast<int>(strlen(device->name)));

  std::cout << "Available devices:\n";

  for (pcap_if_t *device = alldevsp ; device != nullptr ; device = device->next)
  {
    std::cout << ++deviceNo << "." <<  std::left << std::setfill(' ') << std::setw(maxNameLen) << device->name << " - ";
    if (device->description)
      std::cout << device->description << std::endl;
    else
      std::cout << "No description available"<< std::endl;
  }
}

void setSystemIpAddr(pcap_if_t *alldevsp, int chosenDeviceNo)
{
  pcap_if_t *device = getChosenDevice(alldevsp, chosenDeviceNo);

  // Get ipv6 address
  for (pcap_addr_t *pcap_addr = device->addresses; pcap_addr != nullptr; pcap_addr = pcap_addr->next)
  {
    if (pcap_addr->addr->sa_family == AF_INET6)
    {
      for(int i = 0; i < IPV6_ADDR_LENGTH_BYTES; ++i)
        systemIpAddr[i] = ((struct sockaddr_in6*)pcap_addr->addr)->sin6_addr.s6_addr[i];
    }
  }
}

void setSystemMacAddr(pcap_if_t *alldevsp, int chosenDeviceNo)
{
  pcap_if_t *device = getChosenDevice(alldevsp, chosenDeviceNo);

  // Get MAC address
  struct ifreq ifr;
  int s = socket(AF_INET6, SOCK_DGRAM, 0);
  std::strcpy(ifr.ifr_name, device->name);
  ioctl(s, SIOCGIFHWADDR, &ifr);
  for (int i = 0; i < MAC_LENGTH_BYTES; ++i)
    systemMacAddr[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
}

bool isIPv6Packet(const unsigned char *rawData)
{
  if (*(rawData + 12) == 0x86 && *(rawData + 13) == 0xDD)
     return true;
  else
    return false;
}

bool isIcmpPacket(const unsigned char *rawData)
{
  if (*(rawData + 20) == 0x003a)
    return true;
  else
    return false;
}

bool isNdpPacket(const unsigned char *rawData)
{
  if (*(rawData + 54) == 135)
    return true;
  else
    return false;
}

bool isPingPacket(const unsigned char *rawData)
{
  if (*(rawData + 54) == 128)
    return true;
  else
    return false;
}

bool isTcpPacket(const unsigned char *rawData)
{
  if (*(rawData + 20) == 6)
    return true;
  else
    return false;
}

bool isHttpPacket(const unsigned char *rawData, int packetLength)
{
  uint16_t dstPort = ((*(rawData + 56)) << 8) + (*(rawData + 57));
  if (packetLength > 98 && dstPort == 80)
    return true;
  else
    return false;
}

bool packetIntendedForThisPeer(const unsigned char *rawData)
{
  const int halfOfMacLenght = MAC_LENGTH_BYTES/2;
  const int lastThreeBytesOfIpAddr = IPV6_ADDR_LENGTH_BYTES - 3;
  rawData += halfOfMacLenght;

  if (std::equal(rawData, rawData + halfOfMacLenght, systemIpAddr + lastThreeBytesOfIpAddr))
    return true;
  else
    return false;
}

void createPacketFromRawData(const struct pcap_pkthdr* pkthdr, const unsigned char *rawData)
{
  std::unique_ptr<Packet> packet;

  if (packetIntendedForThisPeer(rawData))
    {
    if (isIPv6Packet(rawData))
    {
      if (isIcmpPacket(rawData))
      {
        packet = std::unique_ptr<Packet>(new ICMPv6Packet(rawData));
        if (isNdpPacket(rawData))
        {
            // Because first NDP packet MAC and IP dst addr is group address
          EthFrame *ethFrameCast = dynamic_cast<EthFrame*>(packet.get());
          ethFrameCast->setDstMacAddr(systemMacAddr);

          IPv6Packet *ipv6Packet = dynamic_cast<IPv6Packet*>(packet.get());
          ipv6Packet->setDstIpAddr(systemIpAddr);
        }
      }
      else if (isTcpPacket(rawData))
      {
        if (isHttpPacket(rawData, pkthdr->len))
        {
            std::string version("HTTP/1.1 ");
            std::string status("200 ");
            std::string reason("OK\r\n");
            std::string headers("Date: Sat, 25 May 2002 21:10:32 GTM\r\n"
                                "Server: Apache/1.3.19 (Unix)\r\n"
                                "Last-Modified: Sat, 28 May 2002 20:51:33 GTM\r\n"
                                "Accept-Ranges: bytes\r\nContent-Length: 48\r\n"
                                "Keep-Alive: timeout=15, max=100\r\n"
                                "Content-Type: text/html\r\n\r\n");
            std::string body("<html><body><h1>Hello</h1></body></html>\r\n\r\n");

            packet = std::unique_ptr<Packet>(new HttpPacket(rawData));
            HttpPacket *httpPacketCast = dynamic_cast<HttpPacket*>(packet.get());
            httpPacketCast->setResponse(version, status, reason, headers, body);
        }
        else
        {
          packet = std::unique_ptr<Packet>(new TcpPacket(rawData));
        }
      }
    }
    if (packet)
    {
      packet->transferPacketIntoAnswer();

      const int packetSize = packet->getFrameLength();

      unsigned char data[packetSize];
      packet->transferPacketIntoRawData(data);

      if (handle)
        if (pcap_sendpacket(handle, data , packetSize) !=0 )
          printf("pcap_sendpacket error\n");
    }
  }

}
void callbackFunction(unsigned char *args, const struct pcap_pkthdr* pkthdr, const unsigned char *rawData)
{
  createPacketFromRawData(pkthdr, rawData);
}
