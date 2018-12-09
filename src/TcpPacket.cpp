#include "TcpPacket.h"
#include <iostream>
#include <ctime>

std::unordered_map<uint16_t, uint32_t> TcpPacket::sessions;

using namespace Tcp;

TcpPacket::TcpPacket(const unsigned char *rawData) : IPv6Packet(rawData)
{
  rawData += START_OFFSET;
  std::copy(rawData, rawData + srcPort.size, srcPort.octets);

  rawData += srcPort.size;
  std::copy(rawData, rawData + dstPort.size, dstPort.octets);

  rawData += dstPort.size;
  std::copy(rawData, rawData + seqNum.size, seqNum.octets);

  rawData += seqNum.size;
  std::copy(rawData, rawData + ackNum.size, ackNum.octets);

  rawData += ackNum.size;
  headerLength.octets[0] = (*rawData & 0xF0) >> 4;
  reserved.octets[0] = (*rawData & 0x0E) >> 1;
  flags.octets[0] = *rawData & 0x01;

  rawData += BYTE;
  flags.octets[1] = *rawData;

  rawData += BYTE;
  std::copy(rawData, rawData + windowSize.size, windowSize.octets);

  rawData += windowSize.size;
  std::copy(rawData, rawData + checksum.size, checksum.octets);

  rawData += checksum.size;
  std::copy(rawData, rawData + urgentPointer.size, urgentPointer.octets);

  rawData += urgentPointer.size;
  uint8_t optionsLength = static_cast<uint8_t>(4 * headerLength.octets[0]) - 20;

  for(int i = 0; i < optionsLength; ++i)
  {
    options.push_back(*rawData);
    ++rawData;
  }

  // Specifies the size of the TCP header in 32-bit words
  // unsigned short ipPayloadLength = 4 * headerLength.octets[0];
  // IPv6Packet::setPayloadLength(ipPayloadLength);
  //
  payloadSizeToAck = IPv6Packet::getPayloadLength() - static_cast<uint16_t>((4 * headerLength.octets[0]));
}

void TcpPacket::setSrcPort(uint16_t srcPort)
{
  this->srcPort.octets[0] = (srcPort >> 8) && 0xFF;
  this->srcPort.octets[1] = srcPort && 0xFF;
}
void TcpPacket::setDstPort(uint16_t dstPort)
{
  this->dstPort.octets[0] = (dstPort >> 8) && 0xFF;
  this->dstPort.octets[1] = dstPort && 0xFF;
}

void TcpPacket::setSeqNum(uint32_t sequenceNumber)
{
  seqNum.octets[0] = (sequenceNumber >> 24) & 0xFF;
  seqNum.octets[1] = (sequenceNumber >> 16) & 0xFF;
  seqNum.octets[2] = (sequenceNumber >> 8) & 0xFF;
  seqNum.octets[3] = sequenceNumber & 0xFF;
}
void TcpPacket::setAckNum(uint32_t acknowledgeNumber)
{
  ackNum.octets[0] = (acknowledgeNumber >> 24) & 0xFF;
  ackNum.octets[1] = (acknowledgeNumber >> 16) & 0xFF;
  ackNum.octets[2] = (acknowledgeNumber >> 8) & 0xFF;
  ackNum.octets[3] = acknowledgeNumber & 0xFF;
}

void TcpPacket::setHeaderLength(uint8_t headerLength)
{
  this->headerLength.octets[0] = headerLength;
}

void TcpPacket::setReserved(uint8_t reserved)
{
  this->reserved.octets[0] = reserved;
}

void TcpPacket::setFlags(uint16_t flags)
{
  this->flags.octets[0] = (flags >> 8) & 1;
  this->flags.octets[1] = flags & 0xFF;
}

void TcpPacket::setWindowSize(uint16_t windowSize)
{
  this->windowSize.octets[0] = (windowSize >> 8) && 0xFF;
  this->windowSize.octets[1] = windowSize && 0xFF;
}

void TcpPacket::setChecksum(uint16_t checksum)
{
  uint16_t checksumFirstByte;
  uint16_t checksumSecondByte;

  checksumFirstByte = checksum / 0x0100;
  checksumSecondByte = checksum - checksumFirstByte * 0x0100;

  TcpPacket::checksum.octets[0] = static_cast<unsigned char>(checksumFirstByte);
  TcpPacket::checksum.octets[1] = static_cast<unsigned char>(checksumSecondByte);
}

void TcpPacket::setUrgentPointer(uint16_t urgentPointer)
{
    this->urgentPointer.octets[0] = (urgentPointer >> 8) && 0xFF;
    this->urgentPointer.octets[1] = urgentPointer && 0xFF;
}

void TcpPacket::setOptions(std::vector<unsigned char> options)
{
  this->options = options;
}

uint32_t TcpPacket::getSeqNum()
{
  return ((seqNum.octets[0] << 24) + (seqNum.octets[1] << 16) + (seqNum.octets[2] << 8) + seqNum.octets[3]);
}
uint32_t TcpPacket::getAckNum()
{
  return ((ackNum.octets[0] << 24) + (ackNum.octets[1] << 16) + (ackNum.octets[2] << 8) + ackNum.octets[3]);
}

uint16_t TcpPacket::getSrcPort()
{
  return ((srcPort.octets[0] << 8) + srcPort.octets[1]);
}

uint16_t TcpPacket::getDstPort()
{
    return ((dstPort.octets[0] << 8) + dstPort.octets[1]);
}

uint8_t TcpPacket::getHeaderLength()
{
  return headerLength.octets[0];
}

uint8_t TcpPacket::getReserved()
{
  return reserved.octets[0];
}

uint16_t TcpPacket::getFlags()
{
  return ((flags.octets[0] << 8) + flags.octets[1]);
}

uint16_t TcpPacket::getWindowSize()
{
  return ((windowSize.octets[0] << 8) + windowSize.octets[1]);
}

uint16_t TcpPacket::getChecksum()
{
  return ((checksum.octets[0] << 8) + checksum.octets[1]);
}

uint16_t TcpPacket::getUrgentPointer()
{
  return ((urgentPointer.octets[0] << 8) + urgentPointer.octets[1]);
}

std::vector<unsigned char> TcpPacket::getOptions()
{
  return options;
}

bool TcpPacket::isSynPacket()
{
  if (flags.octets[1] & 2)
    return true;
  else
    return false;
}

bool TcpPacket::isAckPacket()
{
  if (flags.octets[1] & 16)
    return true;
  else
    return false;
}

bool TcpPacket::isFinPacket()
{
  if (flags.octets[1] & 1)
    return true;
  else
    return false;
}

uint32_t TcpPacket::getInitSeqNum()
{
  std::srand(std::time(nullptr));
  return std::rand();
}

void TcpPacket::setSynAckFlags()
{
  uint32_t sequenceNumber = getSeqNum();
  sequenceNumber += 1;
  setAckNum(sequenceNumber);

  sequenceNumber = getInitSeqNum();
  sessions[getDstPort()] = sequenceNumber + 1;
  setSeqNum(sequenceNumber);

  // SYN + ACK flag set
  flags.octets[1] = 18;
}

void TcpPacket::incrementAckNumber()
{
    uint32_t sequenceNumber = getSeqNum();

    sequenceNumber += payloadSizeToAck;

    setAckNum(sequenceNumber);

    sequenceNumber = sessions[getDstPort()];
    setSeqNum(sequenceNumber);
}

void TcpPacket::setFinAckFlags()
{
  uint32_t sequenceNumber = getSeqNum();
  sequenceNumber += 1;

  setAckNum(sequenceNumber);

  sequenceNumber = sessions[getDstPort()];
  setSeqNum(sequenceNumber);
}

uint16_t TcpPacket::calculateChecksum(const char *rawDataOverTcp, uint16_t rawDataSize)
{
  uint64_t checksum = 0;
  uint16_t checksum_result;
  uint16_t checksum_tmp = 0;

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
  }

  for (int i = 0; i < dstIpAddr.size; ++i)
  {
    checksum_tmp  = dstIpAddr.octets[i]*0x0100;
    ++i;
    checksum_tmp += dstIpAddr.octets[i];

    checksum += checksum_tmp;
  }

  unsigned int length = IPv6Packet::getPayloadLength();

  checksum += (uint16_t)length;

  // Next header value 6
  checksum += 0x0006;

  //########pseudo header end

  checksum += (srcPort.octets[0] * 0x0100) + srcPort.octets[1];
  checksum += (dstPort.octets[0] * 0x0100) + dstPort.octets[1];

  checksum += (seqNum.octets[0] * 0x0100) + seqNum.octets[1];
  checksum += (seqNum.octets[2] * 0x0100) + seqNum.octets[3];

  checksum += (ackNum.octets[0] * 0x0100) + ackNum.octets[1];
  checksum += (ackNum.octets[2] * 0x0100) + ackNum.octets[3];

  checksum += (((headerLength.octets[0] << 4) + (reserved.octets[0] << 1) + flags.octets[0]) * 0x0100) + flags.octets[1];

  checksum += (windowSize.octets[0] * 0x0100) + windowSize.octets[1];
  checksum += (urgentPointer.octets[0] * 0x0100) + urgentPointer.octets[1];

  int optionsSize = options.size();

  for(int i = 0; i < optionsSize; ++i)
  {
    checksum_tmp  = options.at(i) * 0x0100;
    ++i;
    if (i < optionsSize)
      checksum_tmp += options.at(i);

    checksum += checksum_tmp;
  }

  for(int i = 0; i < rawDataSize; ++i)
  {
    checksum_tmp  = rawDataOverTcp[i] * 0x0100;
    ++i;
    if (i < rawDataSize)
      checksum_tmp += rawDataOverTcp[i];

    checksum += checksum_tmp;
  }

  checksum = (checksum >> 16) + (checksum & 0xFFFF);
  checksum += (checksum >> 16);

  checksum_result = (uint16_t)checksum;

  return (~checksum_result);
}

void TcpPacket::transferPacketIntoAnswer()
{
  IPv6Packet::transferPacketIntoAnswer();

  if (isSynPacket())
    setSynAckFlags();
  else if (isAckPacket())
    incrementAckNumber();
  else if (isFinPacket())
    setFinAckFlags();

  for (int i = 0; i < srcPort.size; ++i)
    std::swap(srcPort.octets[i], dstPort.octets[i]);

  // Window value 14400
  windowSize.octets[0] = 0x38;
  windowSize.octets[1] = 0x40;

  uint16_t checksum = calculateChecksum();
  setChecksum(checksum);
}

uint32_t TcpPacket::getFrameLength()
{
  return IPv6Packet::getFrameLength() + srcPort.size + dstPort.size + seqNum.size + ackNum.size +
                                        (2 * BYTE) + windowSize.size +
                                        checksum.size + urgentPointer.size + options.size();
}

void TcpPacket::transferPacketIntoRawData(unsigned char *rawPacket)
{
  IPv6Packet::transferPacketIntoRawData(rawPacket);

  rawPacket += START_OFFSET;
  std::copy(srcPort.octets, srcPort.octets + srcPort.size, rawPacket);

  rawPacket += srcPort.size;
  std::copy(dstPort.octets, dstPort.octets + dstPort.size, rawPacket);

  rawPacket += dstPort.size;
  std::copy(seqNum.octets, seqNum.octets + seqNum.size, rawPacket);

  rawPacket += seqNum.size;
  std::copy(ackNum.octets, ackNum.octets + ackNum.size, rawPacket);

  rawPacket += ackNum.size;
  *rawPacket = (headerLength.octets[0] << 4) + (reserved.octets[0] << 1) + flags.octets[0];

  rawPacket += BYTE;
  *rawPacket = flags.octets[1];

  rawPacket += BYTE;
  std::copy(windowSize.octets, windowSize.octets + windowSize.size, rawPacket);

  rawPacket += windowSize.size;
  std::copy(checksum.octets, checksum.octets + checksum.size, rawPacket);

  rawPacket += checksum.size;
  std::copy(urgentPointer.octets, urgentPointer.octets + urgentPointer.size, rawPacket);

  rawPacket += urgentPointer.size;
  for (unsigned char &c : options)
  {
    *rawPacket = c;
    ++rawPacket;
  }
}
