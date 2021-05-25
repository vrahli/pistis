#ifndef HOSTPORT_H
#define HOSTPORT_H


#include <string>

#include "types.h"
#include "KeysFun.h"


class NodeInfo {
 private:
  PROCESS_ID pid;
  std::string host;
  unsigned int port;
  int sock;
  KEY pub;

 public:
  NodeInfo();
  NodeInfo(PROCESS_ID pid, std::string host, unsigned int port, int sock, KEY pub);

  void updateSock(int sock);

  PROCESS_ID getPid();
  std::string getHost();
  unsigned int getPort();
  int getSock();
  KEY getPub();

  bool operator<(const NodeInfo& hp) const;
};


#endif
