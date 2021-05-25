#include <iostream>
#include <cstring> 
#include <fstream>

#include "config.h"
#include "Nodes.h"


void Nodes::addNode(unsigned int id, std::string host, unsigned int port, int sock, KEY pub) {
  NodeInfo hp(id,host,port,sock,pub);
  this->nodes[id]=hp;
}

NodeInfo * Nodes::find(unsigned int id) {
  std::map<unsigned int,NodeInfo>::iterator it = nodes.find(id);

  if (it != nodes.end()) {
    if (DEBUG) { std::cout << KMAG << "found a corresponding NodeInfo entry" << KNRM << std::endl; }
    return &(it->second);
  } else { return NULL; }
}

std::list<PROCESS_ID> Nodes::getIds() {
  std::map<unsigned int,NodeInfo>::iterator it = nodes.begin();
  std::list<PROCESS_ID> l = {};

  while (it != nodes.end()) {
    l.push_back(it->first); it++;
  }

  return l;
}

void Nodes::updateSock(unsigned int id, int sock) {
  std::map<unsigned int,NodeInfo>::iterator it = nodes.find(id);

  if (it != nodes.end()) {
    NodeInfo nfo = it->second;
    nfo.updateSock(sock);
    nodes[id]=nfo;
  }
}

void Nodes::printNodes() {
  std::map<unsigned int,NodeInfo>::iterator it = nodes.begin();

  while (it != nodes.end()) {
    unsigned int id = it->first;
    NodeInfo nfo = it->second;

    if (DEBUG) std::cout << KMAG << "id: " << id << "; host: " << nfo.getHost() << "; port: " << nfo.getPort() << KNRM << std::endl;
    it++;
  }
}

int Nodes::numNodes() {
  std::map<unsigned int,NodeInfo>::iterator it = nodes.begin();

  int count = 0;
  while (it != nodes.end()) { count++; it++; }
  return count;
}


void printIds(std::list<PROCESS_ID> l) {
  std::list<PROCESS_ID>::iterator it = l.begin();

  while (it != l.end()) {
      if (DEBUG) std::cout << KMAG << "id: " << *it << KNRM << std::endl;
    it++;
  }
}


std::list<PROCESS_ID> Nodes::getRandNodes(int x) {
  std::list<PROCESS_ID> l = {};
  std::list<PROCESS_ID> ids = getIds();
  std::list<PROCESS_ID>::iterator it;

  int count = x;
  while (count > 0) {
    count--;
    //std::cout << KMAG << "[[[ iteration ]]]" << KNRM << std::endl;
    it = ids.begin();
    // srand is called in Process.cc
    int r = rand() % ids.size();
    std::advance(it,r);
    l.push_back(*it);
    ids.erase(it);
  }

  //std::cout << KMAG << "*** selected ***" << KNRM << std::endl;
  //printIds(l);
  //std::cout << KMAG << "*** left off ***" << KNRM << std::endl;
  //printIds(ids);

  return l;
}


std::list<PROCESS_ID> Nodes::getRandNodesExcept(std::set<PROCESS_ID> pids, int x) {
  std::list<PROCESS_ID> l = {};
  std::list<PROCESS_ID> ids = getIds();
  std::list<PROCESS_ID>::iterator it;

  for (std::set<PROCESS_ID>::iterator it = pids.begin(); it != pids.end(); ++it) {
      ids.remove(*it);
  }

  int count = x;
  while (count > 0 && ids.begin() != ids.end()) {
    count--;
    //std::cout << KMAG << "[[[ iteration ]]]" << KNRM << std::endl;
    it = ids.begin();
    int r = rand() % ids.size();
    std::advance(it,r);
    l.push_back(*it);
    ids.erase(it);
  }

  if (DEBUG2) { std::cout << KMAG << "x=" << x << ";#removed=" << pids.size() << ";#selected=" << x - count << KNRM << std::endl; }

  //std::cout << KMAG << "*** selected ***" << KNRM << std::endl;
  //printIds(l);
  //std::cout << KMAG << "*** left off ***" << KNRM << std::endl;
  //printIds(ids);

  return l;
}


std::list<PROCESS_ID> Nodes::getRandNodesExcept(PROCESS_ID pid, int x) {
  std::list<PROCESS_ID> l = {};
  std::list<PROCESS_ID> ids = getIds();
  std::list<PROCESS_ID>::iterator it;

  ids.remove(pid);

  int count = x;
  while (count > 0 && ids.begin() != ids.end()) {
    count--;
    //std::cout << KMAG << "[[[ iteration ]]]" << KNRM << std::endl;
    it = ids.begin();
    int r = rand() % ids.size();
    std::advance(it,r);
    l.push_back(*it);
    ids.erase(it);
  }

  //std::cout << KMAG << "*** selected ***" << KNRM << std::endl;
  //printIds(l);
  //std::cout << KMAG << "*** left off ***" << KNRM << std::endl;
  //printIds(ids);

  return l;
}


Nodes::Nodes() {}


Nodes::Nodes(KeysFun kf, int n) {
    if (DEBUG) std::cout << KMAG << "generating " << n << " nodes" << KNRM << std::endl;
    for (int id = 0; id < n; id++) {
        std::string host = "127.0.0.1";
        int port = 8080;
        int sock = NO_SOCKET; // -1 means: no socket yet

        //public key
        KEY pub;
        //newKEY(pub);
#ifdef KK_RSA4096
        pub = RSA_new();
#endif
#ifdef KK_RSA2048
        pub = RSA_new();
#endif
#ifdef KK_EC521
        // nothing special to do for EC
#endif
#ifdef KK_EC256
        // nothing special to do for EC
#endif
#ifdef KK_BLS
        pub = (KEY)malloc(sizeof(element_t));
        kf.initG2(pub);
#endif
        kf.loadPublicKey(id,&pub);

        if (DEBUG) std::cout << KMAG << "id: " << id << "; host: " << host << "; port: " << port << KNRM << std::endl;
        addNode(id,host,port,sock,pub);
    }
}


Nodes::Nodes(KeysFun kf, char *filename) {
  std::ifstream inFile(filename);
  char oneline[MAXLINE];
  char delim[] = " ";
  char *token;

  while (inFile) {
    inFile.getline(oneline,MAXLINE);
    token = strtok(oneline,delim);

    if (token) {
      // id
      int id = atoi(token+3);

      // host
      token=strtok(NULL,delim);
      std::string host = token+5;

      // port
      token=strtok(NULL,delim);
      int port = atoi(token+5);

      //public key
      KEY pub;
      //newKEY(pub);
#ifdef KK_RSA4096
      pub = RSA_new();
#endif
#ifdef KK_RSA2048
      pub = RSA_new();
#endif
#ifdef KK_EC521
      // nothing special to do for EC
#endif
#ifdef KK_EC256
      // nothing special to do for EC
#endif
#ifdef KK_BLS
      pub = (KEY)malloc(sizeof(element_t));
      kf.initG2(pub);
#endif
      kf.loadPublicKey(id,&pub);

      if (DEBUG) std::cout << KMAG << "id: " << id << "; host: " << host << "; port: " << port << KNRM << std::endl;

      int sock = -1; // -1 means: no socket yet
      addNode(id,host,port,sock,pub);
    }
  }

  if (DEBUG) std::cout << KMAG << "closing configuration file" << KNRM << std::endl;
  inFile.close();
  if (DEBUG) std::cout << KMAG << "done parsing the configuration file" << KNRM << std::endl;
}
