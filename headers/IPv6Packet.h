#pragma once
#include <cstdint>
#include "EthFrame.h"

#define IPV6_START_OFFSET 14
#define VERSION_BYTES_LENGTH 1
#define TRAFFIC_CLASS_BYTES_LENGTH 1
#define FLOW_LABEL_BYTES_LENGTH 3
#define PAYLOAD_BYTES_LENGTH 2
#define NEXT_HEADER_BYTES_LENGTH 1
#define HOP_LIMIT_BYTES_LENGTH 1
#define IPV6_ADDR_BYTES_LENGTH 16
#define BYTE 1

namespace IPv6 {

struct Version {
  const uint8_t size = VERSION_BYTES_LENGTH;
  unsigned char octets[VERSION_BYTES_LENGTH];
};

struct TrafficClass {
  const uint8_t size = TRAFFIC_CLASS_BYTES_LENGTH;
  unsigned char octets[TRAFFIC_CLASS_BYTES_LENGTH];
};

struct FlowLabel {
  const uint8_t size = FLOW_LABEL_BYTES_LENGTH;
  unsigned char octets[FLOW_LABEL_BYTES_LENGTH];
};

struct PayloadLength {
  const uint8_t size = PAYLOAD_BYTES_LENGTH;
  unsigned char octets[PAYLOAD_BYTES_LENGTH];
};

struct NextHeader {
  const uint8_t size = NEXT_HEADER_BYTES_LENGTH;
  unsigned char octets[NEXT_HEADER_BYTES_LENGTH];
};

struct HopLimit {
  const uint8_t size = HOP_LIMIT_BYTES_LENGTH;
  unsigned char octets[HOP_LIMIT_BYTES_LENGTH];
};

struct IpAddr {
  const uint8_t size = IPV6_ADDR_BYTES_LENGTH;
  unsigned char octets[IPV6_ADDR_BYTES_LENGTH];
};
}

class IPv6Packet : public EthFrame {
  public:
    IPv6Packet() = default;
    IPv6Packet(const unsigned char *rawData);

    void setVersion(uint8_t version);
    void setTrafficClass(uint8_t trafficClass);
    void setFlowLabel(uint32_t flowLabel);
    void setPayloadLength(unsigned short payloadLength);
    void setNextHeader(uint8_t nextHeader);
    void setHopLimit(uint8_t hopLimit);
    void setDstIpAddr(unsigned char *ipAddr);
    void setSrcIpAddr(unsigned char *ipAddr);

    uint8_t getVersion();
    uint8_t getTrafficClass();
    uint32_t getFlowLabel();
    uint16_t getPayloadLength();
    uint8_t setNextHeader();
    uint8_t setHopLimit();
    IPv6::IpAddr getSrcIpAddr();
    IPv6::IpAddr getDstIpAddr();

    virtual uint32_t getFrameLength();
    virtual void transferPacketIntoAnswer();
    virtual void transferPacketIntoRawData(unsigned char *rawPacket);

  private:
    IPv6::Version version;
    IPv6::TrafficClass trafficClass;
    IPv6::FlowLabel flowLabel;
    IPv6::PayloadLength payloadLength;
    IPv6::NextHeader nextHeader;
    IPv6::HopLimit hopLimit;
    IPv6::IpAddr dstIpAddr;
    IPv6::IpAddr srcIpAddr;
};
