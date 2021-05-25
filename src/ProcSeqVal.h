#ifndef PROCSEQVAL_H
#define PROCSEQVAL_H


#include "Message.h"
#include "ProcSeq.h"


class ProcSeqVal {
 private:
  PROCESS_ID pid;
  SEQUENCE_NUM seq;
  VALUE val;

 public:
  ProcSeqVal(PROCESS_ID p, SEQUENCE_NUM s, VALUE v);
  PROCESS_ID getPid();
  SEQUENCE_NUM getSeq();
  VALUE getVal();
  bool operator<(const ProcSeqVal& ps) const;
};


#endif
