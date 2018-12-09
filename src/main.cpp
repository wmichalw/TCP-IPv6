#include <iostream>
#include <memory>
#include "connectionHandler.h"

#define PROMISCUOUS_MODE 1
#define READ_TIME_OUT_MS 1000
#define PROCESS_ALL_PACKETS -1
#define OPTIMIZE 0

pcap_t* handle = nullptr;

int main()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int status;
  int chosenDev;

  pcap_if_t *alldevsp;

  if (pcap_findalldevs(&alldevsp, errbuf) > 0)
  {
    std::cout << errbuf;
    return -1;
  }

  printAvailableDevices(alldevsp);

  int chosenDeviceNo;

  std::cout << "Choose device\n";
  std::cin >> chosenDeviceNo;

  int numOfDevices = getNumberOfAvailableDevices(alldevsp);

  if(chosenDeviceNo < 1 || chosenDeviceNo > numOfDevices)
  {
    std::cout << "Wrong device number\n";
    return -1;
  }

  setSystemIpAddr(alldevsp, chosenDeviceNo);
  setSystemMacAddr(alldevsp, chosenDeviceNo);

  struct bpf_program fp;
  bpf_u_int32 net;

  pcap_if_t *chosenDevice = getChosenDevice(alldevsp, chosenDeviceNo);

  // Handle connection
  handle = pcap_open_live(chosenDevice->name, BUFSIZ, PROMISCUOUS_MODE, READ_TIME_OUT_MS, errbuf);

  if (handle == nullptr)
  {
		 fprintf(stderr, "Couldn't open device %s: %s\n", chosenDevice->name, errbuf);
		 return -1;
	}

  char filterExp[] = "";

  if (pcap_compile(handle, &fp, filterExp, OPTIMIZE, net) == -1)
  {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filterExp, pcap_geterr(handle));
    return -1;
  }

  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Error setting filter\n");
    return -1;
  }

  pcap_loop(handle, PROCESS_ALL_PACKETS, callbackFunction, nullptr);

  return 0;
}
