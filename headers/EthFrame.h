#pragma once
#include "Packet.h"

#define MAC_BYTES_LENGTH 6
#define ETH_TYPE_BYTES_LENGTH 2

namespace Ethernet {
struct MacAddr{
  const uint8_t size = MAC_BYTES_LENGTH;
  unsigned char octets[MAC_BYTES_LENGTH];
};

struct EthType{
  const uint8_t size  = ETH_TYPE_BYTES_LENGTH;
  unsigned char octets[ETH_TYPE_BYTES_LENGTH];
};
}

class EthFrame : public Packet{
  public:
    EthFrame() = default;
    EthFrame(const unsigned char *rawData);

    void setDstMacAddr(unsigned char *macAddr);
    void setSrcMacAddr(unsigned char *macAddr);
    void setEthType(unsigned char *ethType);

    Ethernet::MacAddr getSrcMacAddr();
    Ethernet::MacAddr getDstMacAddr();
    Ethernet::EthType getEthType();

    virtual uint32_t getFrameLength();
    virtual void transferPacketIntoAnswer();
    virtual void transferPacketIntoRawData(unsigned char *rawPacket);

  private:
    Ethernet::MacAddr dstMacAddr;
    Ethernet::MacAddr srcMacAddr;
    Ethernet::EthType ethType;
};
