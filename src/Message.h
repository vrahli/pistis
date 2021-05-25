#ifndef MSG_H
#define MSG_H

#include "config.h"
#include "types.h"
#include "Sign.h"
#include "broadcast_m.h"


class Message {
 private:
  HEADER hdr;
  PROCESS_ID pid;
  SEQUENCE_NUM seq;
  VALUE val;
  Aggregate esign;
  Aggregate sign;
  MODE mode = MODE_BROADCAST; // default
  int inst  = 0;
  int round = 0;

 public:
  Message(HEADER hdr);
  Message(HEADER hdr, VALUE val);
  Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs);
  Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, MODE mode);
  Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, MODE mode, int inst);
  Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, MODE mode, int inst, int round);
  /*Message(char * data);*/

  HEADER       getHeader();
  PROCESS_ID   getPid();
  SEQUENCE_NUM getSeq();
  VALUE        getVal();
  Aggregate    getEsign();
  Aggregate    getSign();
  MODE         getMode();
  int          getInst();
  int          getRound();

  /*void serialize(char *data);
  void deserialize(char *data);*/

  BroadcastMsg* to_broadcast();
  Message(BroadcastMsg *m);

  void setRound(int rnd);

  int size();
};


#endif
