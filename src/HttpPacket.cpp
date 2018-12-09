#include "HttpPacket.h"
#include <string>
#include <cstring>
#include <iostream>
#include <memory>

HttpPacket::HttpPacket(const unsigned char *rawData) : TcpPacket(rawData)
{
  uint32_t startOffset = TcpPacket::getFrameLength();
  std::string methodString(rawData + startOffset, rawData + startOffset + 6);

  if (methodString.find("GET") != std::string::npos)
    request.method = std::string("GET ");
  else if (methodString.find("POST") != std::string::npos)
    request.method = std::string("POST ");
  else if (methodString.find("PUT") != std::string::npos)
    request.method = std::string("PUT ");
  else if (methodString.find("DELETE") != std::string::npos)
    request.method = std::string("DELETE ");
  else if (methodString.find("HEAD") != std::string::npos)
    request.method = std::string("HEAD ");

  request.size = TcpPacket::getPayloadLength() - startOffset;
}

void HttpPacket::setRequest(std::string method, std::string url, std::string version, std::string headers, std::string body)
{
  request.method  = method;
  request.url     = url;
  request.version = version;
  request.headers = headers;
  request.body    = body;

  request.size = method.size() + url.size() + version.size() + headers.size() + body.size();
}

void HttpPacket::setResponse(std::string version, std::string status, std::string reason, std::string headers, std::string body)
{
  response.version = version;
  response.status  = status;
  response.reason  = reason;
  response.headers = headers;
  response.body    = body;

  isResponse = true;
  response.size = version.size() + status.size() + reason.size() + headers.size() + body.size();
}

std::string HttpPacket::getRequest()
{
  return std::string(request.method + request.url + request.version + request.headers + request.body);
}

std::string HttpPacket::getResponse()
{
  return std::string(response.version + response.status + response.reason + response.headers + response.body);
}

uint32_t HttpPacket::getFrameLength()
{
  if(isResponse)
    return (TcpPacket::getFrameLength() + response.size);
  else
    return (TcpPacket::getFrameLength() + request.size);
}

void HttpPacket::transferPacketIntoAnswer()
{
  unsigned short length = getFrameLength() - IPv6Packet::getFrameLength();
  IPv6Packet::setPayloadLength(length);
  // Fin connection
  TcpPacket::setFlags(0x0019);
  TcpPacket::transferPacketIntoAnswer();

  std::string rawData = response.version + response.status  + response.reason  + response.headers + response.body;
  uint16_t checksum =  TcpPacket::calculateChecksum(rawData.c_str(), rawData.size());
  TcpPacket::setChecksum(checksum);

}

void HttpPacket::transferPacketIntoRawData(unsigned char *rawPacket)
{
  TcpPacket::transferPacketIntoRawData(rawPacket);

  int startOffset = TcpPacket::getFrameLength();
  rawPacket += startOffset;

  std::copy(response.version.c_str(), response.version.c_str() + response.version.size(), rawPacket);

  rawPacket += response.version.size();
  std::copy(response.status.c_str(), response.status.c_str() + response.status.size(), rawPacket);

  rawPacket += response.status.size();
  std::copy(response.reason.c_str(), response.reason.c_str() + response.reason.size(), rawPacket);

  rawPacket += response.reason.size();
  std::copy(response.headers.c_str(), response.headers.c_str() + response.headers.size(), rawPacket);

  rawPacket += response.headers.size();
  std::copy(response.body.c_str(), response.body.c_str() + response.body.size(), rawPacket);
}
