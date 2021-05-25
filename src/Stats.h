#ifndef STATS_H
#define STATS_H


#include <chrono>
#include <string>

class Stats {
private:
    unsigned int id;
    double cryptoTimeSign;
    double cryptoTimeVerif;
    unsigned int numSign;
    unsigned int numSent;
    unsigned int numVerif;
    unsigned int skippedVerify;
    unsigned int numDelayed;    // number of delayed messages
    unsigned int numNonDelayed; // number of messages sent without delay

public:
    Stats();

    unsigned int getId();
    double getCryptoTime();
    double getCryptoTimeSign();
    double getCryptoTimeVerif();
    unsigned int getNumSign();
    unsigned int getNumSent();
    unsigned int getNumVerif();
    unsigned int getSkippedSign();
    unsigned int getNumDelayed();
    unsigned int getNumNonDelayed();

    void setId(unsigned int i);
    void incrementCryptoTimeSign(double v);
    void incrementCryptoTimeVerif(double v);
    //void incrementNumSign();
    //void incrementNumVerif();
    void incrementNumSent();
    void incrementSkippedVerify();
    void incrementNumDelayed();
    void incrementNumNonDelayed();

    std::string to_string();

    friend std::ostream& operator<<(std::ostream& os, const Stats &s);
};


#endif
