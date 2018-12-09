#pragma once
#include <cstdint>
class Packet
{
public:
  virtual uint32_t getFrameLength() = 0;
  virtual void transferPacketIntoAnswer() = 0;
  virtual void transferPacketIntoRawData(unsigned char *) = 0;
};
