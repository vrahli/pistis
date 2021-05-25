#ifndef AGGREGATE_H
#define AGGREGATE_H

#include <set>

#include "config.h"
#include "types.h"
#include "Sign.h"
#include "KeysFun.h"
#include "Stats.h"


class Aggregate {

 private:
    // TODO: if this was a list, then we could have sequential signatures
    // TODO: A map would be faster when we check for inclusion
  std::set<SIGN> aggregate;
  //void fromArray(SIGN *signs);
  std::set<SIGN> getSet();
  void aggregateSet(int bound, KeysFun KF, std::set<SIGN> signs2, Stats &stats);

 public:
  Aggregate();
  //Aggregate(SIGN *signs);
  //Aggregate(std::set<SIGN> signs);
  Aggregate(int bound, KeysFun KF, KEY priv, PROCESS_ID signer, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats &stats);
  //Aggregate(KEY priv, PROCESS_ID signer, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, SIGN *signs);

  void aggregateSign(int bound, KeysFun KF, SIGN sign, Stats& stats);
  void aggregateSign(int bound, KeysFun KF, KEY priv, PROCESS_ID signer, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats& stats);
  /*void aggregateSign(KEY priv, PROCESS_ID signer, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns);*/
  void aggregateWith(int bound, KeysFun KF, Aggregate signs2, Stats &stats);

  // 'ca' is the "aggregate" we got so far
  bool verifyAggregate(KeysFun KF, Aggregate ca, Nodes nodes, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats &stats);
  /*bool verifyAggregate(Nodes nodes, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns);*/

  int numSigners();
  void print();
  void printSigners();
  std::set<PROCESS_ID> getSigners();
  bool containsSigner(PROCESS_ID pid);
  bool containsSign(SIGN sign);
  int size();

  bool contains(Aggregate aggr);
};

#endif
