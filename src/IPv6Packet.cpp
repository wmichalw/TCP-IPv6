#include "IPv6Packet.h"
#include <algorithm>
#include <iostream>

using namespace IPv6;

IPv6Packet::IPv6Packet(const unsigned char *rawData) : EthFrame(rawData)
{
   rawData += IPV6_START_OFFSET;
   version.octets[0] = ((*rawData & 0xF0) >> 4);
   trafficClass.octets[0] = ((*rawData & 0x0F) << 4) + ((*(rawData + BYTE) & 0xF0) >> 4);

   rawData += BYTE;
   flowLabel.octets[0] = (*rawData & 0x0F);

   rawData += BYTE;
   flowLabel.octets[1] = *rawData;

   rawData += BYTE;
   flowLabel.octets[2] = *rawData;

   rawData += BYTE;
   std::copy(rawData, rawData + payloadLength.size, payloadLength.octets);

   rawData += payloadLength.size;
   std::copy(rawData, rawData + nextHeader.size, nextHeader.octets);

   rawData += nextHeader.size;
   std::copy(rawData, rawData + hopLimit.size, hopLimit.octets);

   rawData += hopLimit.size;
   std::copy(rawData, rawData + srcIpAddr.size, srcIpAddr.octets);

   rawData += srcIpAddr.size;
   std::copy(rawData, rawData + dstIpAddr.size, dstIpAddr.octets);
}

void IPv6Packet::setVersion(uint8_t version)
{
  this->version.octets[0] = version;
}

void IPv6Packet::setTrafficClass(uint8_t trafficClass)
{
  this->trafficClass.octets[0] = trafficClass;
}

void IPv6Packet::setFlowLabel(uint32_t flowLabel)
{
  this->flowLabel.octets[0] = (flowLabel >> 16) && 0xFF;
  this->flowLabel.octets[1] = (flowLabel >> 8) && 0xFF;
  this->flowLabel.octets[2] = flowLabel  && 0xFF;
}

void IPv6Packet::setPayloadLength(unsigned short payloadLength)
{
  this->payloadLength.octets[0] = (payloadLength & 0xFF00) >> 8;
  this->payloadLength.octets[1] = (payloadLength & 0x00FF);
}

void IPv6Packet::setNextHeader(uint8_t nextHeader)
{
  this->nextHeader.octets[0] = nextHeader;
}

void IPv6Packet::setHopLimit(uint8_t hopLimit)
{
  this->hopLimit.octets[0] = hopLimit;
}

void IPv6Packet::setDstIpAddr(unsigned char *ipAddr)
{
  std::copy(ipAddr, ipAddr + dstIpAddr.size, dstIpAddr.octets);
}

void IPv6Packet::setSrcIpAddr(unsigned char *ipAddr)
{
  std::copy(ipAddr, ipAddr + srcIpAddr.size, srcIpAddr.octets);
}

uint8_t IPv6Packet::getVersion()
{
  return version.octets[0];
}

uint8_t IPv6Packet::getTrafficClass()
{
  return trafficClass.octets[0];
}

uint32_t IPv6Packet::getFlowLabel()
{
  return ((flowLabel.octets[0] << 16) + (flowLabel.octets[1] << 8) + flowLabel.octets[2]);
}

uint16_t IPv6Packet::getPayloadLength()
{
  return ((payloadLength.octets[0] << 8) + payloadLength.octets[1]);
}

uint8_t IPv6Packet::setNextHeader()
{
  return nextHeader.octets[0];
}

uint8_t IPv6Packet::setHopLimit()
{
  return hopLimit.octets[0];
}

IpAddr IPv6Packet::getSrcIpAddr()
{
  return srcIpAddr;
}

IpAddr IPv6Packet::getDstIpAddr()
{
  return dstIpAddr;
}

uint32_t IPv6Packet::getFrameLength()
{
  return EthFrame::getFrameLength() + 4 + PAYLOAD_BYTES_LENGTH + NEXT_HEADER_BYTES_LENGTH + HOP_LIMIT_BYTES_LENGTH + IPV6_ADDR_BYTES_LENGTH * 2;
}

void IPv6Packet::transferPacketIntoAnswer()
{
  EthFrame::transferPacketIntoAnswer();

  for (int i = 0; i < dstIpAddr.size; ++i)
    std::swap(srcIpAddr.octets[i], dstIpAddr.octets[i]);
}

void IPv6Packet::transferPacketIntoRawData(unsigned char *rawPacket)
{
  EthFrame::transferPacketIntoRawData(rawPacket);

  rawPacket += IPV6_START_OFFSET;
  *rawPacket = (version.octets[0] << 4) + ((trafficClass.octets[0] & 0xF0) >> 4);

  rawPacket += BYTE;
  *rawPacket = ((trafficClass.octets[0] & 0x0F) << 4) + flowLabel.octets[0];

  rawPacket += BYTE;
  *rawPacket = flowLabel.octets[1];

  rawPacket += BYTE;
  *rawPacket = flowLabel.octets[2];

  rawPacket += BYTE;
  std::copy(payloadLength.octets, payloadLength.octets + payloadLength.size, rawPacket);

  rawPacket += payloadLength.size;
  std::copy(nextHeader.octets, nextHeader.octets + nextHeader.size, rawPacket);

  rawPacket += nextHeader.size;
  std::copy(hopLimit.octets, hopLimit.octets + hopLimit.size, rawPacket);

  rawPacket += hopLimit.size;
  std::copy(srcIpAddr.octets, srcIpAddr.octets + srcIpAddr.size, rawPacket);

  rawPacket += srcIpAddr.size;
  std::copy(dstIpAddr.octets, dstIpAddr.octets + dstIpAddr.size, rawPacket);
}
