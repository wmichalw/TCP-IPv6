#include "ICMPv6Packet.h"
#include "EthFrame.h"
#include <memory>
#include <iostream>

using namespace ICMPv6;

ICMPv6Packet::ICMPv6Packet(const unsigned char *rawData) : IPv6Packet(rawData)
{
  rawData += ICMPV6_START_OFFSET;
  std::copy(rawData, rawData + type.size, type.octets);

  rawData += type.size;
  std::copy(rawData, rawData + code.size, code.octets);

  rawData += code.size;
  std::copy(rawData, rawData + checksum.size, checksum.octets);

  rawData += checksum.size;
  uint16_t icmpLength = IPv6Packet::getPayloadLength();

  for(int i = 0; i < icmpLength; ++i)
  {
    messageBody.push_back(*rawData);
    ++rawData;
  }
}

uint32_t ICMPv6Packet::getFrameLength()
{
  return IPv6Packet::getFrameLength() + TYPE_BYTES_LENGTH + CODE_BYTES_LENGTH + CHECKSUM_BYTES_LENGTH + messageBody.size();
}

void ICMPv6Packet::shortenChecksumToUnsignedShort(unsigned long &checksum)
{
  if (checksum & 0xFFFF0000)
  {
    checksum &=0xFFFF;
    checksum++;
  }
}

void ICMPv6Packet::setType(uint8_t type)
{
  this->type.octets[0] = type;
}

void ICMPv6Packet::setCode(uint8_t code)
{
  this->code.octets[0] = code;
}

void ICMPv6Packet::setChecksum(uint16_t checksum)
{
  uint16_t checksumFirstByte;
	uint16_t checksumSecondByte;

  checksumFirstByte = checksum / 0x0100;
	checksumSecondByte = checksum - checksumFirstByte * 0x0100;

  ICMPv6Packet::checksum.octets[0] = static_cast<unsigned char>(checksumFirstByte);
  ICMPv6Packet::checksum.octets[1] = static_cast<unsigned char>(checksumSecondByte);
}

uint8_t ICMPv6Packet::getType()
{
  return type.octets[0];
}
uint8_t ICMPv6Packet::getCode()
{
  return code.octets[0];
}

uint16_t ICMPv6Packet::getChecksum()
{
  return ((checksum.octets[0] << 8) + checksum.octets[1]);
}

void ICMPv6Packet::transferIntoNeighborAdvertisment()
{
  // Neighbor adverisment 0x0087
  type.octets[0] = 136;

  messageBody.clear();

  // Router Solicited Override
  messageBody.push_back(0x60);
  messageBody.push_back(0x00);
  messageBody.push_back(0x00);
  messageBody.push_back(0x00);

  IPv6::IpAddr srcIpAddr = IPv6Packet::getSrcIpAddr();
  Ethernet::MacAddr srcMacAddr = EthFrame::getSrcMacAddr();

   for (int i = 0; i < srcIpAddr.size; ++i)
     messageBody.push_back(srcIpAddr.octets[i]);

  // Type target link layer
  messageBody.push_back(0x0002);
  messageBody.push_back(0x0001);

  for (int i = 0; i < srcMacAddr.size; ++i)
    messageBody.push_back(srcMacAddr.octets[i]);
}

uint16_t ICMPv6Packet::calculateChecksum()
{
  uint64_t checksum = 0;
  uint16_t checksum_result;
  uint16_t checksum_tmp = 0;

  // start from ip addr

  //######## pseudo header

  // Sum src and dst ip
  IPv6::IpAddr srcIpAddr = IPv6Packet::getSrcIpAddr();
  IPv6::IpAddr dstIpAddr = IPv6Packet::getDstIpAddr();

  for (int i = 0; i < srcIpAddr.size; ++i)
  {
    checksum_tmp  = srcIpAddr.octets[i]*0x0100;
    ++i;
    checksum_tmp += srcIpAddr.octets[i];

    checksum += checksum_tmp;
    shortenChecksumToUnsignedShort(checksum);
  }

  for (int i = 0; i < dstIpAddr.size; ++i)
  {
    //checksum_tmp=(*tmp_pointer)*0x0100;
    checksum_tmp  = dstIpAddr.octets[i]*0x0100;
    ++i;
    checksum_tmp += dstIpAddr.octets[i];

    checksum+=checksum_tmp;
    shortenChecksumToUnsignedShort(checksum);
  }

  unsigned int length = getFrameLength() - IPv6Packet::getFrameLength();

  // Icmpv6 length
  checksum += (uint16_t)length;
  shortenChecksumToUnsignedShort(checksum);

  // Next header value 58
  checksum += 0x003A;
  shortenChecksumToUnsignedShort(checksum);

  //########pseudo header end

  // icmpv6 start
  checksum_tmp  = type.octets[0] * 0x0100;
  checksum_tmp += code.octets[0];

  checksum += checksum_tmp;
  shortenChecksumToUnsignedShort(checksum);

  int messageBodySize = messageBody.size();

  for(int i = 0; i < messageBodySize; ++i)
  {
    checksum_tmp  = messageBody.at(i) * 0x0100;
    ++i;
    if (i < messageBodySize)
      checksum_tmp += messageBody.at(i);

    checksum += checksum_tmp;
    shortenChecksumToUnsignedShort(checksum);
  }

  checksum_result = (unsigned short)checksum;

  return (~(checksum_result & 0xFFFF));
}

void ICMPv6Packet::transferPacketIntoAnswer()
{
  IPv6Packet::transferPacketIntoAnswer();

  if (type.octets[0] == 135)
    transferIntoNeighborAdvertisment();
  else if (type.octets[0] == 128)
  {
    // Is ready in constructor
    type.octets[0] = 129;
  }

  uint16_t checksum = calculateChecksum();
  setChecksum(checksum);
}

void ICMPv6Packet::transferPacketIntoRawData(unsigned char *rawPacket)
{
  IPv6Packet::transferPacketIntoRawData(rawPacket);

  rawPacket += ICMPV6_START_OFFSET;
  std::copy(type.octets, type.octets + type.size, rawPacket);

  rawPacket += type.size;
  std::copy(code.octets, code.octets + code.size, rawPacket);

  rawPacket += code.size;
  std::copy(checksum.octets, checksum.octets + checksum.size, rawPacket);

  rawPacket += checksum.size;

  for (unsigned char &c : messageBody)
  {
    *rawPacket = c;
    ++rawPacket;
  }
}
