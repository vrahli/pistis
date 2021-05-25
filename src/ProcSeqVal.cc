#include "Message.h"
#include "ProcSeq.h"
#include "ProcSeqVal.h"

ProcSeqVal::ProcSeqVal(PROCESS_ID p, SEQUENCE_NUM s, VALUE v) {
  pid = p;
  seq = s;
  val = v;
}

PROCESS_ID ProcSeqVal::getPid() {
  return pid;
}

SEQUENCE_NUM ProcSeqVal::getSeq() {
  return seq;
}

VALUE ProcSeqVal::getVal() {
  return val;
}

// TODO: finish
bool ProcSeqVal::operator<(const ProcSeqVal& ps) const {
  if (pid < ps.pid) { return true; }
  else {
      if (seq < ps.seq) { return true; }
      else {
          if (val < ps.val) { return true; }
          else { return false; }
      }
  }
}
