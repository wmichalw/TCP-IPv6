#include <algorithm>
#include <iostream>
#include "EthFrame.h"

using namespace Ethernet;

EthFrame::EthFrame(const unsigned char *rawData)
{
  std::copy(rawData, rawData + dstMacAddr.size, dstMacAddr.octets);

  rawData += dstMacAddr.size;
  std::copy(rawData, rawData + srcMacAddr.size, srcMacAddr.octets);

  rawData += srcMacAddr.size;
  std::copy(rawData, rawData + ethType.size, ethType.octets);
}

void EthFrame::setDstMacAddr(unsigned char *macAddr)
{
  std::copy(macAddr, macAddr + dstMacAddr.size, dstMacAddr.octets);
}

void EthFrame::setSrcMacAddr(unsigned char *macAddr)
{
  std::copy(macAddr, macAddr + srcMacAddr.size, srcMacAddr.octets);
}

void EthFrame::setEthType(unsigned char *ethType) {
  std::copy(ethType, ethType + this->ethType.size, this->ethType.octets);
}

MacAddr EthFrame::getSrcMacAddr() { return srcMacAddr; }

MacAddr EthFrame::getDstMacAddr() { return srcMacAddr; }

EthType EthFrame::getEthType() { return ethType; }

uint32_t EthFrame::getFrameLength()
{
  return MAC_BYTES_LENGTH * 2 + ETH_TYPE_BYTES_LENGTH;
}

void EthFrame::transferPacketIntoAnswer()
{
  for (int i = 0; i < dstMacAddr.size; ++i)
    std::swap(srcMacAddr.octets[i], dstMacAddr.octets[i]);
}

void EthFrame::transferPacketIntoRawData(unsigned char *rawPacket)
{
  std::copy(dstMacAddr.octets, dstMacAddr.octets + dstMacAddr.size, rawPacket);

  rawPacket += dstMacAddr.size;
  std::copy(srcMacAddr.octets, srcMacAddr.octets + srcMacAddr.size, rawPacket);

  rawPacket += srcMacAddr.size;
  std::copy(ethType.octets, ethType.octets + ethType.size, rawPacket);
}
