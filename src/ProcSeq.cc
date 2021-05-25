#include "Message.h"
#include "ProcSeq.h"

ProcSeq::ProcSeq(PROCESS_ID p, SEQUENCE_NUM s) {
  pid = p;
  seq = s;
}

PROCESS_ID ProcSeq::getPid() {
  return pid;
}

SEQUENCE_NUM ProcSeq::getSeq() {
  return seq;
}

bool ProcSeq::operator<(const ProcSeq& ps) const {
  if (pid < ps.pid) { return true; }
  else {
      if (seq < ps.seq) { return true; }
      else { return false; }
  }
}
