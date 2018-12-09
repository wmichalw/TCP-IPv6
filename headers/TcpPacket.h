#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>
#include "IPv6Packet.h"

#define START_OFFSET 54
#define PORT_BYTE_LENGTH 2
#define SEQ_NUM_BYTE_LENGTH 4
#define ACK_NUM_BYTE_LENGTH 4
#define HEADER_BYTE_LENGTH 1
#define FLAGS_BYTE_LENGTH 2
#define WINDOW_BYTE_LENGTH 2
#define CHECKSUM_BYTE_LENGTH 2
#define URGENT_POINTER_BYTE_LENGTH 2
#define BYTE 1

namespace Tcp {
struct Port {
  const uint8_t size = PORT_BYTE_LENGTH;
  unsigned char octets[PORT_BYTE_LENGTH];
};

struct SeqNum {
  const uint8_t size = SEQ_NUM_BYTE_LENGTH;
  unsigned char octets[SEQ_NUM_BYTE_LENGTH];
};

struct AckNum {
  const uint8_t size = ACK_NUM_BYTE_LENGTH;
  unsigned char octets[ACK_NUM_BYTE_LENGTH];
};

struct HeaderLength {
  const uint8_t size = BYTE;
  unsigned char octets[BYTE];
};

struct Reserved {
  const uint8_t size = BYTE;
  unsigned char octets[BYTE];
};

struct Flags {
  const uint8_t size = FLAGS_BYTE_LENGTH;
  unsigned char octets[FLAGS_BYTE_LENGTH];
};

struct WindowSize {
  const uint8_t size = WINDOW_BYTE_LENGTH;
  unsigned char octets[WINDOW_BYTE_LENGTH];
};

struct Checksum {
  const uint8_t size = CHECKSUM_BYTE_LENGTH;
  unsigned char octets[CHECKSUM_BYTE_LENGTH];
};

struct UrgentPointer {
  const uint8_t size = URGENT_POINTER_BYTE_LENGTH;
  unsigned char octets[URGENT_POINTER_BYTE_LENGTH];
};
}

class TcpPacket : public IPv6Packet
{
public:
  TcpPacket() = default;
  TcpPacket(const unsigned char *rawData);

  void setSrcPort(uint16_t srcPort);
  void setDstPort(uint16_t dstPort);
  void setSeqNum(uint32_t sequenceNumber);
  void setAckNum(uint32_t acknowledgeNumber);
  void setHeaderLength(uint8_t headerLength);
  void setReserved(uint8_t reserved);
  void setFlags(uint16_t flags);
  void setWindowSize(uint16_t windowSize);
  void setChecksum(uint16_t checksum);
  void setUrgentPointer(uint16_t urgentPointer);
  void setOptions(std::vector<unsigned char> options);

  uint16_t getSrcPort();
  uint16_t getDstPort();
  uint32_t getSeqNum();
  uint32_t getAckNum();
  uint8_t getHeaderLength();
  uint8_t getReserved();
  uint16_t getFlags();
  uint16_t getWindowSize();
  uint16_t getChecksum();
  uint16_t getUrgentPointer();
  std::vector<unsigned char> getOptions();

  uint16_t calculateChecksum(const char *rawDataOverTcp = nullptr, uint16_t rawDataSize = 0);

  virtual uint32_t getFrameLength();
  virtual void transferPacketIntoAnswer();
  virtual void transferPacketIntoRawData(unsigned char *rawPacket);

private:
  Tcp::Port srcPort;
  Tcp::Port dstPort;
  Tcp::SeqNum seqNum;
  Tcp::AckNum ackNum;
  Tcp::HeaderLength headerLength;
  Tcp::Reserved reserved;
  Tcp::Flags flags;
  Tcp::WindowSize windowSize;
  Tcp::Checksum checksum;
  Tcp::UrgentPointer urgentPointer;
  std::vector<unsigned char> options;
  static std::unordered_map<uint16_t, uint32_t> sessions;

  bool isSynPacket();
  bool isAckPacket();
  bool isFinPacket();
  void setSynAckFlags();
  void setFinAckFlags();
  void incrementAckNumber();
  uint32_t getInitSeqNum();
  uint16_t payloadSizeToAck;
};
