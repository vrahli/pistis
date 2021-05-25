#ifndef SIGN_H
#define SIGN_H

#include <iostream>
#include <set>
#include <array>

#include "types.h"
#include "Value.h"
#include "KeysFun.h"
#include "Nodes.h"
#include "Stats.h"


class SIGN {

 private:
#ifdef MULTISIG
  std::multiset<PROCESS_ID> signers = {}; // the signers
#else
  PROCESS_ID signer;
#endif
  //PROCESS_ID signer;
  std::array<unsigned char,SIGN_LEN> sign;

 public:
  SIGN();
  /*SIGN(PROCESS_ID signer, char c);
  SIGN(PROCESS_ID signer, std::array<unsigned char,SIGN_LEN> s);
  SIGN(PROCESS_ID signer, unsigned char s[SIGN_LEN]);*/
  SIGN(KeysFun KF, KEY priv, PROCESS_ID signer, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
  /*SIGN(KEY priv, PROCESS_ID signer, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, std::set<SIGN> signs);*/
  std::array<unsigned char,SIGN_LEN> getSign();
#ifdef MULTISIG
  std::multiset<PROCESS_ID> getSigners();
#else
  PROCESS_ID getSigner();
#endif
  std::string toString();
  void copy(unsigned char sign[SIGN_LEN]);
  void combine(KeysFun KF, SIGN sign);
  void printSigners();
  int numSigners();
  int size();

  bool verifySign(KeysFun KF, KEY pub,     PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats& stats);
  bool verifySign(KeysFun KF, Nodes nodes, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats& stats);
  /*bool verifySign(KEY pub,     PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, std::set<SIGN> esigns);
  bool verifySign(Nodes nodes, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, std::set<SIGN> esigns);*/

  void test(KeysFun KF, PROCESS_ID id, std::string text, KEY priv, KEY pub, unsigned char sign[SIGN_LEN]);

  friend std::ostream& operator<<(std::ostream& os, const SIGN &s);
  bool operator<(const SIGN& s) const;
  bool operator==(const SIGN& s) const;
};

#endif
