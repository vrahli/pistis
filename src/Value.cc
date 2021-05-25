#include <string>

#include "Value.h"


VALUE::VALUE() {}

VALUE::VALUE(unsigned int num, unsigned int v) {
    for (int i = 0; i < num; i++) {
        val.insert(val.begin(),v);
    }
}

int VALUE::size() {
    return (val.size() * sizeof(unsigned int));
}

// TODO
void VALUE::next() {
}

std::string VALUE::to_string() {
    std::string s;
    for (std::vector<unsigned int>::const_iterator it=val.begin(); it!=val.end(); ++it) {
      s = s + std::to_string((unsigned int)(*it));
    }
    return s;
}

std::ostream& operator<<(std::ostream& os, const VALUE& v) {
  for (std::vector<unsigned int>::const_iterator it=v.val.begin(); it!=v.val.end(); ++it) {
      unsigned int i = (unsigned int)(*it);
      os << std::to_string(i);
  }
  return os;
}

bool VALUE::operator<(const VALUE& v) const {
    return (val < v.val);
}
