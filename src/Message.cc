#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "Message.h"


HEADER       Message::getHeader()    { return this->hdr;       }
PROCESS_ID   Message::getPid()       { return this->pid;       }
SEQUENCE_NUM Message::getSeq()       { return this->seq;       }
VALUE        Message::getVal()       { return this->val;       }
Aggregate    Message::getEsign()     { return this->esign;     }
Aggregate    Message::getSign()      { return this->sign;      }
MODE         Message::getMode()      { return this->mode;      }
int          Message::getInst()      { return this->inst;      }
int          Message::getRound()     { return this->round;     }


/*void Message::serialize(char *data) {
  HEADER *a = (HEADER*)data;
  *a = this->hdr; a++;

  int *b = (int*)a;
  *b = this->pid; b++;
  *b = this->seq; b++;
  *b = this->val; b++;

  Aggregate *c = (Aggregate*)b; c++;
  Aggregate *d = (Aggregate*)c; d++;

  MODE *e = (MODE*)d;
  *e = this->mode; e++;
}*/


/*void Message::deserialize(char *data) {
  HEADER *a = (HEADER*)data;
  this->hdr = *a; a++;

  int *b = (int*)a;
  this->pid = *b; b++;
  this->seq = *b; b++;
  this->val = *b; b++;

  Aggregate *c = (Aggregate*)b; c++;
  Aggregate *d = (Aggregate*)c; d++;

  MODE *e = (MODE*)d;
  this->mode = *e; e++;
}*/


Message::Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs) {
  this->hdr   = hdr;
  this->pid   = pid;
  this->seq   = seq;
  this->val   = val;
  this->esign = esigns;
  this->sign  = signs;
}


Message::Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, MODE mode) {
  this->hdr   = hdr;
  this->pid   = pid;
  this->seq   = seq;
  this->val   = val;
  this->esign = esigns;
  this->sign  = signs;
  this->mode  = mode;
}


Message::Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, MODE mode, int inst) {
  this->hdr   = hdr;
  this->pid   = pid;
  this->seq   = seq;
  this->val   = val;
  this->esign = esigns;
  this->sign  = signs;
  this->mode  = mode;
  this->inst  = inst;
}


Message::Message(HEADER hdr, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, MODE mode, int inst, int round) {
  this->hdr   = hdr;
  this->pid   = pid;
  this->seq   = seq;
  this->val   = val;
  this->esign = esigns;
  this->sign  = signs;
  this->mode  = mode;
  this->inst  = inst;
  this->round = round;
}


MODE defMode = MODE_BROADCAST;
PROCESS_ID defPid = 0;
SEQUENCE_NUM defSeq = 0;
VALUE defVal;
int defInst = 0;
int defRound = 0;


Message::Message(HEADER hdr) {
    this->hdr   = hdr;
    this->pid   = defPid;
    this->seq   = defSeq;
    this->val   = defVal;
    this->esign = {};
    this->sign  = {};
    this->mode  = defMode;
    this->inst  = defInst;
    this->round = defRound;
}

Message::Message(HEADER hdr, VALUE val) {
    this->hdr   = hdr;
    this->pid   = defPid;
    this->seq   = defSeq;
    this->val   = val;
    this->esign = {};
    this->sign  = {};
    this->mode  = defMode;
    this->inst  = defInst;
    this->round = defRound;
}

/*Message::Message(char *data) {
  deserialize(data);
}*/


BroadcastMsg* Message::to_broadcast() {
    BroadcastMsg *m = new BroadcastMsg();
    m->setHdr(this->hdr);
    m->setPid(this->pid);
    m->setSeq(this->seq);
    m->setVal(this->val);
    m->setEsign(this->esign);
    m->setSign(this->sign);
    m->setMode(this->mode);
    m->setInst(this->inst);
    m->setRound(this->round);
    return m;
}

Message::Message(BroadcastMsg *m) {
    this->hdr   = (HEADER)(m->getHdr());
    this->pid   = m->getPid();
    this->seq   = m->getSeq();
    this->val   = m->getVal();
    this->esign = m->getEsign();
    this->sign  = m->getSign();
    this->mode  = (MODE)(m->getMode());
    this->inst  = m->getInst();
    this->round = m->getRound();
}

int Message::size() {
    int s1 = sizeof(HEADER);
    int s2 = sizeof(PROCESS_ID);
    int s3 = sizeof(SEQUENCE_NUM);
    int s4 = this->val.size();
    int s5 = this->esign.size();
    int s6 = this->sign.size();
    int s7 = sizeof(MODE);
    int s8 = sizeof(int);
    int s9 = sizeof(int);

    /*if (DEBUG) { std::cout << KBLU << "size header=" << s1 << KNRM << std::endl; }
    if (DEBUG) { std::cout << KBLU << "size pid="    << s2 << KNRM << std::endl; }
    if (DEBUG) { std::cout << KBLU << "size seq="    << s3 << KNRM << std::endl; }
    if (DEBUG) { std::cout << KBLU << "size val="    << s4 << KNRM << std::endl; }
    if (DEBUG) { std::cout << KBLU << "size esign="  << s5 << KNRM << std::endl; }
    if (DEBUG) { std::cout << KBLU << "size sign="   << s6 << KNRM << std::endl; }
    if (DEBUG) { std::cout << KBLU << "size mode="   << s7 << KNRM << std::endl; }*/

    return s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8 + s9;
}


void Message::setRound(int rnd) {
  this->round=rnd;
}
