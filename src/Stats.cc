#include "Stats.h"
#include <sstream>
#include <omnetpp.h>

Stats::Stats() {
    id              = 0;
    cryptoTimeSign  = 0.0;
    cryptoTimeVerif = 0.0;
    numSign         = 0;
    numSent         = 0;
    numVerif        = 0;
    skippedVerify   = 0;
    numDelayed      = 0;
    numNonDelayed   = 0;
}

unsigned int Stats::getId() {
    return id;
}

double Stats::getCryptoTime() {
    return (cryptoTimeSign + cryptoTimeVerif);
}

double Stats::getCryptoTimeSign() {
    return cryptoTimeSign;
}

double Stats::getCryptoTimeVerif() {
    return cryptoTimeVerif;
}

unsigned int Stats::getNumSign() {
    return numSign;
}

unsigned int Stats::getNumSent() {
    return numSent;
}

unsigned int Stats::getNumVerif() {
    return numVerif;
}

unsigned int Stats::getSkippedSign() {
    return numVerif;
}

unsigned int Stats::getNumDelayed() {
    return numDelayed;
}

unsigned int Stats::getNumNonDelayed() {
    return numNonDelayed;
}

void Stats::setId(unsigned int i) {
    id = i;
}

void Stats::incrementCryptoTimeSign(double v) {
    //double old = cryptoTime;
    cryptoTimeSign += v;
    numSign++;
    //std::cout << "old=" << old << ";added=" << v << ";new=" << cryptoTime << std::endl;
}

void Stats::incrementCryptoTimeVerif(double v) {
    //double old = cryptoTime;
    cryptoTimeVerif += v;
    numVerif++;
    //std::cout << "old=" << old << ";added=" << v << ";new=" << cryptoTime << std::endl;
}

// void Stats::incrementNumSign() {
//     numSign++;
// }

// void Stats::incrementNumVerif() {
//     numVerif++;
// }

void Stats::incrementNumSent() {
    numSent++;
}

void Stats::incrementSkippedVerify() {
    skippedVerify++;
}

void Stats::incrementNumDelayed() {
    numDelayed++;
}

void Stats::incrementNumNonDelayed() {
    numNonDelayed++;
}

std::string Stats::to_string() {
    std::ostringstream os;
    os << "[id=" << id
       << ";crypto-total(micro-sec)=" << (cryptoTimeSign + cryptoTimeVerif)
       << ";crypto-sign="  << cryptoTimeSign
       << ";crypto-verif=" << cryptoTimeVerif
       << ";#sign="        << numSign
       << ";#sent="        << numSent
       << ";#verif="       << numVerif
       << ";#skipped="     << skippedVerify
       << ";#delayed="     << numDelayed
       << ";#non-delayed=" << numNonDelayed << "]";
    return os.str();
}

std::ostream& operator<<(std::ostream& os, const Stats& s) {
    os << std::to_string(s.cryptoTimeSign);
    return os;
}
