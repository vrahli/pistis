#include <string>

#include "NodeInfo.h"


NodeInfo::NodeInfo() {
  this->pid  = 0;
  this->host = "127.0.0.1";
  this->port = 8080;
  this->sock = -1;
  this->pub  = NULL;
}


NodeInfo::NodeInfo(PROCESS_ID pid, std::string host, unsigned int port, int sock, KEY pub) {
  this->pid  = pid;
  this->host = host;
  this->port = port;
  this->sock = sock;
  this->pub  = pub;
}


void NodeInfo::updateSock(int sock) {
  this->sock = sock;
}


PROCESS_ID   NodeInfo::getPid()  { return this->pid;  }
std::string  NodeInfo::getHost() { return this->host; }
unsigned int NodeInfo::getPort() { return this->port; }
int          NodeInfo::getSock() { return this->sock; }
KEY          NodeInfo::getPub()  { return this->pub;  }

// TODO: finish
bool NodeInfo::operator<(const NodeInfo& hp) const {
  if (port < hp.port) { return true; }
  return false;
}
