#include "Aggregate.h"
#include <chrono>

std::set<SIGN> Aggregate::getSet() {
  return this->aggregate;
}

int Aggregate::numSigners() {
#ifdef MULTISIG
    int count = 0;
    for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it) {
        count += ((SIGN)(*it)).numSigners();
    }
    return count;
#else
    return this->aggregate.size();
#endif
}

int Aggregate::size() {
    int count = 0;
    for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it) {
        count += ((SIGN)(*it)).size();
    }
    return count;
}

void Aggregate::print() {
  std::cout << "[";
  for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it) {
    std::cout << " " << *it << " ";
  }
  std::cout << "]" << std::endl;
}


void Aggregate::printSigners() {
    int count = 0;
    for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it, count++) {
        std::cout << KGRN << "-aggregate " << count << KNRM << std::endl;
        ((SIGN)*it).printSigners();
    }
}


std::set<PROCESS_ID> Aggregate::getSigners() {
    std::set<PROCESS_ID> signers = {};
    for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it) {
        SIGN sign = (SIGN)*it;
#ifdef MULTISIG
        std::multiset<PROCESS_ID> k = sign.getSigners();
        for (std::multiset<PROCESS_ID>::iterator it = k.begin(); it != k.end(); ++it) {
            PROCESS_ID id = *it;
            signers.insert(id);
        }
#else
        signers.insert(sign.getSigner());
#endif
    }
    return signers;
}


Aggregate::Aggregate() {}


bool Aggregate::containsSigner(PROCESS_ID pid) {
    std::set<PROCESS_ID> l = this->getSigners();

    std::set<PROCESS_ID>::iterator it = l.begin();
    if (l.find(pid) == l.end()) { return false; }
    //std::cout << "---" << std::endl;
    //printSigners();
    //std::cout << "pid:" << pid << std::endl;
    return true;
}


bool Aggregate::contains(Aggregate aggr) {
    std::set<PROCESS_ID> l = this->getSigners();
    std::set<PROCESS_ID> k = aggr.getSigners();

    for (std::set<PROCESS_ID>::iterator it = k.begin(); it != k.end(); ++it) {
        // if an element from aggr (k) is not in this (l), then aggr (k) is not contained in this (l)
        if (l.find((PROCESS_ID)(*it)) == l.end()) { return false; }
    }
    return true;
}


void Aggregate::aggregateSign(int bound, KeysFun KF, SIGN sign, Stats& stats) {
  //std::cout << KGRN << "pushing signature" << mysign << KNRM << std::endl;
  //if (DEBUG) { std::cout << KGRN << "pushing signature" << KNRM << std::endl; }
  //auto start = std::chrono::high_resolution_clock::now();
#ifdef MULTISIG
  if (this->aggregate.size() > 1) {
      if (DEBUG) { std::cout << KRED << "bad aggregate of size " << this->aggregate.size() << KNRM << std::endl; }
  }
  std::set<SIGN>::iterator it = this->aggregate.begin();
  if (it != this->aggregate.end()) {
      if (DEBUG) { std::cout << KGRN << "pushing to non-empty aggregate" << KNRM << std::endl; }
      SIGN s = *it;
      s.combine(KF,sign);
      s.printSigners();
      // TODO: Why doesn't this work?
      //*it = s;
      this->aggregate.erase(it);
      this->aggregate.insert(s);
  } else {
      if (DEBUG) { std::cout << KGRN << "pushing to empty aggregate" << KNRM << std::endl; }
      this->aggregate.insert(sign);
  }
#else
  if (this->numSigners() < bound) {
      this->aggregate.insert(sign);
  }
#endif
  //std::cout << KGRN << "pushed signature" << mysign << KNRM << std::endl;
  //if (DEBUG) { std::cout << KGRN << "pushed signature" << KNRM << std::endl; }
  //if (DEBUG) { printSigners(); }
  //auto end = std::chrono::high_resolution_clock::now();
  //std::cout << "adding-S1:" << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << std::endl;
  //stats.incrementCryptoTime(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
}


void Aggregate::aggregateSign(int bound, KeysFun KF, KEY priv, PROCESS_ID signer, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats& stats) {
    if (!this->containsSigner(signer) && this->numSigners() < bound) {
        if (DEBUG3) { std::cout << KBGRN << signer << ":OUT" << KNRM << std::endl; }
        if (DEBUG3) { std::cout << KGRN << signer << ":signing@" << phase << KNRM << std::endl; }
        if (DEBUG) { std::cout << KGRN << "making signature for " << signer << KNRM << std::endl; }
        auto start = std::chrono::steady_clock::now();
        SIGN mysign(KF,priv,signer,phase,pid,seq,val);
        auto end = std::chrono::steady_clock::now();
        //std::cout << "adding-S2:" << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << std::endl;
        double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        stats.incrementCryptoTimeSign(time);
        //stats.incrementNumSign();
        //std::cout << KGRN << ":" << stats.getId() << ":sign-time:" << time << KNRM << std::endl;
        aggregateSign(bound,KF,mysign,stats);
    } else {
        if (DEBUG3) { std::cout << KBGRN << signer << ":IN" << KNRM << std::endl; this->printSigners(); }
    }
}


Aggregate::Aggregate(int bound, KeysFun KF, KEY priv, PROCESS_ID signer, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats &stats) {
  aggregateSign(bound,KF,priv,signer,phase,pid,seq,val,stats);
}


/*void Aggregate::aggregateSign(KEY priv, PROCESS_ID signer, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns) {
  if (DEBUG) { std::cout << KGRN << "making signature for " << signer << KNRM << std::endl; }

  SIGN mysign(priv,signer,pid,seq,val,esigns.getSet());
  aggregateSign(mysign);
}*/


void Aggregate::aggregateSet(int bound, KeysFun KF, std::set<SIGN> signs, Stats &stats) {
//    auto start = std::chrono::high_resolution_clock::now();
    int i = 0;
    if (DEBUG) { std::cout << KGRN << "started aggregating " << signs.size() << " signatures within set of size " << numSigners() << KNRM << std::endl; }
    for (std::set<SIGN>::iterator it = signs.begin(); it != signs.end() && numSigners() < bound; ++it, i++) {
        SIGN sign = (SIGN)*it;
        aggregateSign(bound,KF,sign,stats);
    }
    if (DEBUG) { std::cout << KGRN << "inserted " << i << " signature, now has " << numSigners() << " signatures " << KNRM << std::endl; }
//    auto end = std::chrono::high_resolution_clock::now();
//    cryptoTime += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}


void Aggregate::aggregateWith(int bound, KeysFun KF, Aggregate signs, Stats &stats) {
    aggregateSet(bound, KF, signs.getSet(), stats);
}


bool Aggregate::containsSign(SIGN sign) {
    for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it) {
        SIGN s = (SIGN)(*it);
        if (sign == s) { return true; }
    }
    return false;
}


bool Aggregate::verifyAggregate(KeysFun KF, Aggregate ca, Nodes nodes, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats &stats) {
  auto start = std::chrono::steady_clock::now();
  //std::cout << KGRN << ":" << stats.getId() << "#verif-aggregate=" << this->aggregate.size() << KNRM << std::endl;
  for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it) {
        SIGN sign = (SIGN)(*it);
        // we only verify if 'ca' doesn't contain 'sign'
        if (ca.containsSign(sign)) {
            if (DEBUG7) { std::cout << KGRN << "skipped verification of signature, already in (syntactic check)" << KNRM << std::endl; }
            stats.incrementSkippedVerify();
        } else {
            if (DEBUG7) { std::cout << KBGRN << "verifying new signature" << KNRM << std::endl; }
            bool verif = sign.verifySign(KF,nodes,phase,pid,seq,val,stats);
            if (!verif) { return false; }
        }
  }
  //if (DEBUG) { std::cout << KGRN << "checked aggregate" << KNRM << std::endl; }
  auto end = std::chrono::steady_clock::now();
  double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
  stats.incrementCryptoTimeVerif(time);
  return true;
}


/*bool Aggregate::verifyAggregate(Nodes nodes, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns) {
    if (DEBUG) { std::cout << KGRN << "checking aggregate of size " << this->aggregate.size() << KNRM << std::endl; }
    for (std::set<SIGN>::iterator it=this->aggregate.begin(); it!=this->aggregate.end(); ++it) {
        SIGN sign = (SIGN)(*it);
        if (!sign.verifySign(nodes,pid,seq,val,esigns.getSet())) { return false; }
    }
    //if (DEBUG) { std::cout << KGRN << "checked aggregate" << KNRM << std::endl; }
    return true;
}*/
