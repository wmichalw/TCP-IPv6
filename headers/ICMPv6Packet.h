#pragma once
#include "IPv6Packet.h"
#include <cstdint>
#include <vector>

#define ICMPV6_START_OFFSET 54
#define TYPE_BYTES_LENGTH 1
#define CODE_BYTES_LENGTH 1
#define CHECKSUM_BYTES_LENGTH 2

namespace ICMPv6 {
struct Type {
  const uint8_t size = TYPE_BYTES_LENGTH;
  unsigned char octets[TYPE_BYTES_LENGTH];
};

struct Code {
  const uint8_t size = CODE_BYTES_LENGTH;
  unsigned char octets[CODE_BYTES_LENGTH];
};

struct Checksum {
  const uint8_t size = CHECKSUM_BYTES_LENGTH;
  unsigned char octets[CHECKSUM_BYTES_LENGTH];
};
}

class ICMPv6Packet : public IPv6Packet {
public:
  ICMPv6Packet() = default;
  ICMPv6Packet(const unsigned char *rawData);

  void setType(uint8_t type);
  void setCode(uint8_t code);
  void setChecksum(uint16_t checksum);
  uint8_t getType();
  uint8_t getCode();
  uint16_t getChecksum();

  virtual uint32_t getFrameLength();
  virtual void transferPacketIntoAnswer();
  virtual void transferPacketIntoRawData(unsigned char *rawPacket);

private:
  ICMPv6::Type type;
  ICMPv6::Code code;
  ICMPv6::Checksum checksum;
  std::vector<unsigned char> messageBody;

  uint16_t calculateChecksum();
  void shortenChecksumToUnsignedShort(unsigned long &checksum);
  void transferIntoNeighborAdvertisment();
};
