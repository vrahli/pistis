#ifndef PROCSEQ_H
#define PROCSEQ_H


#include "Message.h"


class ProcSeq {
 private:
  PROCESS_ID pid;
  SEQUENCE_NUM seq;

 public:
  ProcSeq(PROCESS_ID p, SEQUENCE_NUM s);
  PROCESS_ID getPid();
  SEQUENCE_NUM getSeq();
  bool operator<(const ProcSeq& ps) const;
};


#endif
