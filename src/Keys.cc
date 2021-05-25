#include <iostream>

#include "config.h"
#include "KeysFun.h"


int main0(int argc, char const *argv[]) {
  // Geting inputs  
  unsigned int myid = 0;
  if (argc > 1) { sscanf(argv[1], "%d", &myid); }
  std::cout << KNRM << "[my id is: " << myid << "]" << KNRM << std::endl;

  KeysFun KF;

  KF.generateRsa4096Keys(myid);
  return 0;
}
