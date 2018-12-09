#include "TcpPacket.h"
#include <string>

namespace Http {
struct Request {
  uint16_t size = 0;
  std::string method;
  std::string url;
  std::string version;
  std::string headers;
  std::string body;
};

struct Response {
  uint16_t size = 0;
  std::string version;
  std::string status;
  std::string reason;
  std::string headers;
  std::string body;
};
}

class HttpPacket : public TcpPacket {
public:
  HttpPacket() = default;
  HttpPacket(const unsigned char *rawData);

  void setRequest(std::string method, std::string url, std::string version, std::string headers, std::string body);
  void setResponse(std::string version, std::string status, std::string reason, std::string headers, std::string body);

  std::string getRequest();
  std::string getResponse();

  virtual uint32_t getFrameLength();
  virtual void transferPacketIntoAnswer();
  virtual void transferPacketIntoRawData(unsigned char *rawPacket);

private:
  Http::Request request;
  Http::Response response;
  bool isResponse = false;
};
