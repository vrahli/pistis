#ifndef NODES_H
#define NODES_H


#include <map>
#include <list>
#include <set>

#include "types.h"
#include "NodeInfo.h"
#include "KeysFun.h"


class Nodes {
 private:
  std::map<unsigned int,NodeInfo> nodes;

 public:
  Nodes();
  Nodes(KeysFun kf, int n);
  Nodes(KeysFun kf, char *filename);
  void addNode(unsigned int id, std::string host, unsigned int port, int sock, KEY pub);

  void updateSock(unsigned int id, int sock);

  NodeInfo * find(unsigned int id);
  std::list<PROCESS_ID> getIds();

  void printNodes();
  int numNodes();
  std::list<PROCESS_ID> getRandNodes(int x);
  std::list<PROCESS_ID> getRandNodesExcept(std::set<PROCESS_ID> pids, int x);
  std::list<PROCESS_ID> getRandNodesExcept(PROCESS_ID pid, int x);
};


#endif
