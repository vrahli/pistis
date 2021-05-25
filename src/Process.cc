#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <omnetpp.h>
#include <cstring>
#include <map>
#include <tuple>
#include <list>
#include <iostream>
#include <fstream>
#include <algorithm>
//#include <thread>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <mutex>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>


#include "broadcast_m.h"
#include "Message.h"
//#include "Sign.h"
#include "Aggregate.h"
#include "ProcSeq.h"
#include "KeysFun.h"
#include "Nodes.h"

#include <omnetpp.h>


using namespace omnetpp;


// TODO: move these map to separate classes
// - 1st bool argument is true if a lie has been discovered, default is false
// - 2nd bool argument is true if still sending echos,       default is true
// - 3rd set  argument contains the nodes from which we have seen large enough aggregates
//    for the corresponding data and to which we therefore do not need to send messages anymore
// - 4th set  argument contains the nodes to which the msg has not been sent to
typedef std::tuple<bool,bool,PIDS,PIDS,Aggregate> RechoEntry;

// - 1st bool argument is true if timed out for this entry,  default is false
// - 2nd set  argument contains the nodes from which we have seen large enough aggregates
//    for the corresponding data and to which we therefore do not need to send messages anymore
// - 3rd set  argument contains the nodes to which the msg has not been sent to
typedef std::tuple<bool,PIDS,PIDS,Aggregate> RdeliverEntry;

class Process : public cSimpleModule {

    static simtime_t timeToDeliver;
    static Stats *stats;
    static double *cryptoTimesDeliver;
    static double *outBdwTotal;

    static int numFinish;
    static int countDelivers;

    // To count the number of nodes that have become passive
    static int countPassives;

    // To count the number of nodes that have finished
    static int countFinished;

private:

    // A switch to run the protocol in RT-ByzCast mode
    bool rtByzCastMode = false;

    // A switch to turn on/off recovery
    bool switch_recovery = true;
    // switch_loss_send is true if we want to lose messages when we send them rather than we receive them
    bool switch_loss_send = true;
    // to select the recipients in a rotating fashion as opposed to randomly
    bool switch_rotating_send = true;
    // to end the simulation after the last deliver is sent (as opposed to waiting until all messages are sent/received)
    bool switch_end_simu_delv = false;

    // A switch to use the optimization that we don't send to a node if we know that it has already received enough signatures
    bool opt_switch_full  = true;
    // TODO: this should not be a switch, we should always do it:
    // A switch to update the signatures at each diffuse
    bool opt_switch_renew = true;
    // A switch to use the optimization that we don't handle message that only contains signatures we have already received
    bool opt_already_all_received = true;

    // A switch to stop the system as soon as 2f+1 nodes have delivered
    bool switch_stop_as_soon_as_quorum_deliverd = false;

    // to clear the memory when finished
    bool CLEAR = true;

    unsigned int counter = 0;   // event counter
    unsigned int numFinishedBcaster = 0; // number of nodes for which we are done delivering all numBcast messages
    bool endSimu = false; // true to end the simulation, i.e., to stop handling messages
    bool someActivity = false;

    int nProcesses    = 0;
    int nGates        = 0;
    int selfid;
    bool bcastingNode = false;         // by default selfid is not a broadcasting node
    int bcastPeriod   = 3;             // by default we broadcast every 3*timeout
    int numBcast      = 1;             // total number of broadcasts, by default: 1
    int bcastInstance = 0;             // current broadcast instance
    bool GC           = true;          // we garbage collect by default
    STATUS status     = STATUS_ACTIVE; // a node is active by default
    bool isByz        = false;         // a node is not Byzantine by default
    int numPassive    = 0;             // by default nobody is passive
    int sizeVal       = 1;             // size of a value in bytes
    int probaLosses   = 0;             // probability of losses, by default: 0
    int numBcaster    = 1;             // number of broadcasting nodes, by default: 1
    std::string passiveOutput;
    std::string durationOutput;
    std::string statsOutput;

    KeysFun KF;

    simsignal_t signal;

    cOutVector outBdwVector;

    cMessage **channelTimers;
    cMessage *activeMsg;

    cQueue *outQueues;

    std::map<ProcSeq, std::map<VALUE,RechoEntry>> Recho;
    std::map<ProcSeq, std::map<VALUE,RdeliverEntry>> Rdeliver;

    std::map<PROCESS_ID, SEQUENCE_NUM> highest;

    LOCTIME timeout;         // timeout in microseconds
    LOCTIME D;               // max transmission delay in microseconds
    unsigned int PD;         // process stay passive (PD*D)ms
    unsigned int maxF;       // number of faults
    unsigned int numByz;     // number of current Byzantine faults
    unsigned int numRand;    // number of nodes to send messages to
    unsigned int quorumSize; // size of a quorum
    unsigned int aggBound;   // maximum size of an aggregate
    Nodes nodes;             // collection of the other nodes
    KEY priv;                // private key

    void printRecho();
    void printRdeliver();
    //void checkRecho();
    void triggerTimeoutBroadcast(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    void triggerTimeoutEcho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    void triggerTimeoutDeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    /*void triggerTimeout(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode);*/
    /*void tDiffuse(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode);*/
    void tDiffuseLoop(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode);
    void triggerDiffuse(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode);
    //void deliverNewMessage(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs);
    void deliverMessage(PID sender, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs);
    void handleBroadcast(PID sender,Message bcast);
    void handleEcho(PID sender,Message echo);
    void handleDeliver(PID sender,Message del);
    void handleTransfer(PID sender,Message msg);
    void handleStart(PID sender,Message msg);
    void handleTimeout(PID sender,Message timeout);
    void handleDiffuse(PID sender,Message diffuse);
    void handleRecover(PID sender,Message msg);
    void handleActive(PID sender,Message msg);
    void handleMessage(PID sender, Message msg);
    void sendMsgNotLost(PIDS full, Message msg);
    void sendMsg(PIDS full, Message msg);
    void triggerDeliverIfActive(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    void triggerDeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    void stopSendingEchos(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    bool stillEchoing(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    bool newEcho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate aggr);
    bool newDeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esig, Aggregate sig);
    bool verifyBroadcast(Message msg);
    bool verifyEcho(Message msg);
    bool verifyDeliver(Message msg);
    bool verifyTransfer(Message msg);
    bool verifyMessage(Message msg);
    void broadcastValue(VALUE val,SEQUENCE_NUM seq);
    void scheduleAndBroadcast(VALUE val);
    void initializeHighest();
    void garbageCollect(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    void garbageCollectUpTo(PROCESS_ID pid, SEQUENCE_NUM seq, SEQUENCE_NUM h);
    bool validSequenceNumber(PROCESS_ID pid, SEQUENCE_NUM seq);
    void cancelActiveMessage();
    void becomePassive();
    void becomeByz();
    void enterPassiveMode(int n, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, unsigned int nsig);
    int gateToProcess(int i);
    PIDS getFullInRecho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    PIDS getFullInRdeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    Aggregate getSignsInRecho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    Aggregate getSignsInRdeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    std::string getTag();
    PIDS others(PIDS full);
    std::vector<PROCESS_ID> selectRecipients_random(PIDS full, Message msg);
    std::vector<PROCESS_ID> selectRecipients_rounds(PIDS full, Message msg);
    PIDS selectRechoTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    PIDS selectRdeliverTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val);
    void updateRechoTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, PIDS tosend);
    void updateRdeliverTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, PIDS tosend);
    RechoEntry updateRechoEntryTosend(RechoEntry e, PIDS tosend);
    RdeliverEntry updateRdeliverEntryTosend(RdeliverEntry e, PIDS tosend);
    void checkEndSimulation(PROCESS_ID pid, SEQUENCE_NUM seq, MODE mode, int inst);
    int id2channel(int pid);
    void printIf(PIDV all, Message msg);
    int getNumRep();
    int getLastRound();
    void test();

protected:
    //virtual BroadcastMsg *generateMessage();
    //virtual void forwardMessage(BroadcastMsg *msg);
    virtual void initialize() override;
    virtual void finish() override;
    virtual void handleMessage(cMessage *msg) override;
    //virtual void sendMessage(BroadcastMsg *msg, int destId);
};

int Process::countPassives;
int Process::countDelivers;
int Process::countFinished;
Stats *Process::stats;
double *Process::cryptoTimesDeliver;
double *Process::outBdwTotal;
simtime_t Process::timeToDeliver;
int Process::numFinish;

Define_Module(Process);

bool      Recho2lie    (RechoEntry e) { return std::get<0>(e); }
bool      Recho2still  (RechoEntry e) { return std::get<1>(e); }
PIDS      Recho2full   (RechoEntry e) { return std::get<2>(e); }
PIDS      Recho2tosend (RechoEntry e) { return std::get<3>(e); }
Aggregate Recho2aggr   (RechoEntry e) { return std::get<4>(e); }

RechoEntry mkRechoEntry(bool lie, bool still, PIDS full, PIDS tosend, Aggregate aggr) {
    return std::make_tuple(lie,still,full,tosend,aggr);
}

bool      Rdeliver2tout   (RdeliverEntry e) { return std::get<0>(e); }
PIDS      Rdeliver2full   (RdeliverEntry e) { return std::get<1>(e); }
PIDS      Rdeliver2tosend (RdeliverEntry e) { return std::get<2>(e); }
Aggregate Rdeliver2aggr   (RdeliverEntry e) { return std::get<3>(e); }

RdeliverEntry mkRdeliverEntry(bool tout, PIDS full, PIDS tosend, Aggregate aggr) {
    return std::make_tuple(tout,full,tosend,aggr);
}

std::string phase2string(PHASE phase) {
    switch (phase) {
    case PHASE_ECHO:      return "ECHO-PH";
    case PHASE_DELIVER:   return "DELIVER-PH";
    }
    return "ERROR-PH";
}

std::string status2string(STATUS s) {
    switch (s) {
    case STATUS_ACTIVE:     return "ACTIVE-ST";
    case STATUS_PASSIVE:    return "PASSIVE-ST";
    case STATUS_RECOVERING: return "RECOVERING-ST";
    }
    return "ERROR-ST";
}

std::string mode2string(MODE mode) {
    switch (mode) {
    case MODE_BROADCAST: return "BROADCAST-MD";
    case MODE_ECHO:      return "ECHO-MD";
    case MODE_DELIVER:   return "DELIVER-MD";
    }
    return "ERROR-MD";
}

std::string header2string(HEADER hdr) {
    switch (hdr) {
    case HDR_BROADCAST: return "BROADCAST-HDR";
    case HDR_ECHO:      return "ECHO-HDR";
    case HDR_DELIVER:   return "DELIVER-HDR";
    case HDR_TRANSFER:  return "TRANSFER-HDR";
    case HDR_START:     return "START-HDR";
    case HDR_DIFFUSE:   return "DIFFUSE-HDR";
    case HDR_TIMEOUT:   return "TIMEOUT-HDR";
    case HDR_RECOVER:   return "RECOVER-HDR";
    case HDR_ACTIVE:    return "ACTIVE-HDR";
    }
    std::string s = "ERROR-HDR(" + std::to_string(hdr) + ")";
    return s;
}


int Process::getNumRep() {
    return ceil(double(timeout) / double(D));
}


std::string Process::getTag() {
    return ("[" + std::to_string(this->selfid) + "|#" + std::to_string(this->counter) + "-T=" + simTime().str() + "-" + std::to_string(status) + "]");
}


// The sequence number of a process id is valid if it is at least as high as the one we recorded in 'highest'.
// We don't care about the sequence numbers strictly lower than we sequence number we recorded in 'highest'
// because we garbage collected those.
bool Process::validSequenceNumber(PROCESS_ID pid, SEQUENCE_NUM seq) {
    if (GC) {
        std::map<PROCESS_ID,SEQUENCE_NUM>::iterator itH = this->highest.find(pid);
        if (itH != this->highest.end()) {
            // found a corresponding entry
            SEQUENCE_NUM h = itH->second;
            return (seq >= h);
        } else { return true; }
    } else { return true; }
}


void Process::initializeHighest() {
    for (int i = 0; i < nProcesses; i++) {
        highest[i] = 0;
    }
}


PIDS Process::others(PIDS full) {
    PIDS others;
    for (int i = 0; i <= nGates; i++) {
        if (i != this->selfid && full.find(i) == full.end()) {  others.insert(i); }
    }
    return others;
}


void Process::broadcastValue(VALUE val,SEQUENCE_NUM seq) {
    if (DEBUG0) { std::cout << KYEL << getTag() << "broadcasting (val=" << val << ",seq=" << seq << ")" << KNRM << std::endl; }

    // TODO: execute proof-of-connectivity in piggyback mode

    ProcSeq ps(this->selfid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it = this->Recho.find(ps);

    if (it != this->Recho.end()) {
        if (DEBUG) { std::cout << KBLU << "skipping broadcast because found a corresponding entry" << KNRM << std::endl; }
        if (DEBUG) { printRecho(); }
    } else {

        if (DEBUG) { std::cout << KBLU << "broadcast entry not found" << KNRM << std::endl; }

        // aggregate signatures, l is the list of echo signatures
        Aggregate l;
        if (DEBUG3) { std::cout << KGRN << selfid << ":aggregating-SEND-BCAST" << KNRM << std::endl; }
        l.aggregateSign(aggBound,KF,this->priv,this->selfid,PHASE_ECHO,this->selfid,seq,val,stats[selfid]);

        // - 1st boolean=false means that no lie has been discovered so far
        // - 2nd boolean=true  means that we're still sending echos
        // - 3rd set={}        means nobody flagged as full (sent big enough aggregates)
        bool lie     = false;
        bool echoing = true;
        PIDS full    = {};
        PIDS tosend  = others(full);

        // Create an echo certificate
        std::map<VALUE,RechoEntry> m;
        m[val]=mkRechoEntry(lie,echoing,full,tosend,l);
        this->Recho[ps]=m;

        // Start diffusing the echo
        Aggregate k; // empty aggregate
        triggerDiffuse(this->selfid,seq,val,k,l,this->timeout,MODE_BROADCAST);
    }
}


void Process::scheduleAndBroadcast(VALUE val) {
    if (bcastInstance < numBcast) {
        if (status == STATUS_ACTIVE) {
            if (bcastInstance < numBcast - 1) {
                // Schedule the next broadcast
                val.next();
                Message msg(HDR_START,val);
                SimTime st = simTime() + (((double)(this->timeout*this->bcastPeriod)) / st.getScale());
                if (DEBUG) { std::cout << KBLU << getTag() << "scheduling start at time " << st << "(scale:" << st.getScale() << ")" << KNRM << std::endl; }
                scheduleAt(st, msg.to_broadcast());
            }

            // some debugging
            if (DEBUG) { std::cout << KBLU << getTag() << "# of scheduled messages: " << cSimulation::getActiveSimulation()->getFES()->getLength() << KNRM << std::endl; }

            // broadcast the current value
            broadcastValue(val,bcastInstance);
            bcastInstance++;
        } else {
            if (switch_recovery) {
                // re-schedule the broadcast
                Message msg(HDR_START,val);
                SimTime st = simTime() + (((double)(this->timeout)) / st.getScale());
                if (DEBUG0) { std::cout << KBYEL << getTag() << "re-scheduling broadcast " << bcastInstance << KNRM << std::endl; }
                scheduleAt(st, msg.to_broadcast());
            }
        }
    }
}


void Process::becomeByz() {
    std::cout << KBLU << getTag() << " starting Byzantine" << KNRM << std::endl;
    // non-communicating
    isByz  = true;
    // and passive
    status = STATUS_PASSIVE;
    countPassives++;
}


void Process::test() {
  unsigned char s[SIGN_LEN];
  std::string text = "foobar";
  SIGN sig;
  KEY pub;
  KF.loadPublicKey(this->selfid,&pub);
  sig.test(KF,this->selfid,text,priv,pub,s);
}


void Process::initialize() {
    nGates = gateSize("gate");
    //if (DEBUG0) { std::cout << "Found " << nGates << " gates" << endl; }

    nProcesses           = nGates + 1;
    selfid               = getIndex();
    bcastInstance        = 0;                      // sequence number
    numBcaster           = par("numBcaster");      // number of processes that broadcast (the first 'numBcaster' nodes)
    bcastPeriod          = par("bcastPeriod");     // time between 2 broadcasts
    numBcast             = par("numBcast");        // number of messages to broadcast per nodes
    GC                   = par("GC");              // whether or not to garbage collect
    timeout              = par("timeout");         // timeout
    D                    = par("maxDelay");        // max transmission delay
    PD                   = par("passiveDuration"); // time that a process stays passive before becoming active again
    maxF                 = par("maxFaults");       // number of faults
    numByz               = par("numByz");          // current number of Byzantine nodes
    numRand              = par("numRand");         // number of nodes to send messages to
    probaLosses          = par("probaLosses");     // probability of message losses
    numPassive           = par("numPassive");      // number of initial passive nodes
    sizeVal              = par("sizeVal");         // size of a value
    switch_recovery      = par("recovery");        // whether or not to recover passive nodes
    switch_loss_send     = par("lossSend");        // whether to drop messages when we send the, or when we receive them
    switch_rotating_send = par("rotatingSend");    // whether to send messages by rotating through the nodes or randomly
    switch_end_simu_delv = par("endSimuDeliver");
    passiveOutput        = par("passiveOutput").stringValue();
    durationOutput       = par("durationOutput").stringValue();
    statsOutput          = par("statsOutput").stringValue();
    rtByzCastMode        = par("rtByzCastMode");
    CLEAR                = par("clear");
    switch_stop_as_soon_as_quorum_deliverd = par("stopEarly");

    quorumSize = (2*maxF)+1;
    //aggBound   = quorumSize;
    aggBound   = nProcesses;

    // WARNING: if this switch is on we don't yet clear the memory (this needs to be implemented)
    //if (switch_stop_as_soon_as_quorum_deliverd) { CLEAR = false; }

    // The first numBcaster nodes are broadcasting nodes
    bcastingNode    = selfid < numBcaster;

    // nProcesses = correct + numPassive + numByz
    // The last numPassive processes are Byzantine/non-communicating by default
    if (nProcesses - numByz <= selfid) { becomeByz(); }
    // The numPassive before the Byzantine ones are passive by default
    if ((nProcesses - numPassive - numByz) <= selfid && selfid < (nProcesses - numByz)) { becomePassive(); }

    // if in RT-ByzCast mode, we set the fanout to the total number of nodes,
    // and we disable PISTIS's optimizations
    if (rtByzCastMode) {
        numRand = nProcesses-1;
        opt_switch_full = false;
        opt_already_all_received = false;
    }

    if (DEBUG12) std::cout << KYEL << getTag()
            << "#nodes="             << nProcesses
            << "; numBcaster="       << numBcaster
            << "; bcasting?="        << bcastingNode
            << "; period?="          << bcastPeriod
            << "; #bcast="           << numBcast
            << "; GC?="              << GC
            << "; status?="          << status
            << "; timeout?="         << timeout
            << "; delay?="           << D
            << "; passiveDuration?=" << PD
            << "; #faults?="         << maxF
            << "; #byz?="            << numByz
            << "; isByz?="           << isByz
            << "; #rand?="           << numRand
            << "; value-size="       << sizeVal
            << "; recovery?="        << switch_recovery
            << "; rtByzCastMode?="   << rtByzCastMode
            << "]" << KNRM << std::endl;

    // The node with id=0 is in charge of initializing the global 'countPassives'
    if (selfid == 0) {
        countDelivers = 0;
        countPassives = 0;
        stats = new Stats[nProcesses];
        cryptoTimesDeliver = new double[nProcesses];
        outBdwTotal = new double[nProcesses];
        for (int i=0; i<nProcesses; i++) {
            stats[i] = Stats();
            stats[i].setId(i);
            cryptoTimesDeliver[i] = 0.0;
            outBdwTotal[i] = 0.0;
        }
        numFinish = 0;
    }


    channelTimers = new cMessage*[nGates];
    for (int i = 0; i < nGates; i++) {
        channelTimers[i] = new cMessage(std::to_string(i).c_str());
        if (DEBUG) { std::cout << KBLU << getTag() << " ** creating channel timer (id=" << channelTimers[i]->getId() << ") for " << i << "/" << nGates << KNRM << std::endl; }
    }

    outQueues = new cQueue[nGates];

    signal = registerSignal("outBdw");

//    EV << selfid << endl;
//    for (int i = 0; i < nProcesses; i++) {
//        EV << i << " -> " << processToGate[i] << "; ";
//    }
//    EV << endl;

    // initialize random seed
    struct timeval t1;
    gettimeofday(&t1, NULL);
    srand(t1.tv_usec * t1.tv_sec);

    // initialize the 'highest' map
    initializeHighest();

#ifdef KK_BLS
    // initialize the BLS g + pairing
    if (DEBUG) { std::cout << KBLU << "Initialize BLS g" << KNRM << std::endl; }
    KF.setBlsG();
#endif

    // Loads the public keys of the nodes
    nodes = Nodes(KF,nProcesses);

    // Load private key
#ifdef KK_RSA4096
    priv = RSA_new();
#endif
#ifdef KK_RSA2048
    priv = RSA_new();
#endif
#ifdef KK_EC521
    // nothing special to do for EC
#endif
#ifdef KK_EC256
    // nothing special to do for EC
#endif
#ifdef KK_BLS
    this->priv = (KEY)(new element_t);//(KEY)malloc(sizeof(element_t));
    KF.initZr(this->priv);
    //if (DEBUG) { element_printf(KCYN "secret key %d = %B\n" KNRM, this->selfid, *(this->priv)); }
#endif
    KF.loadPrivateKey(this->selfid,&this->priv);

    //test();

    if (DEBUG) std::cout << KBLU << "ready to do initial bcast" << KNRM << std::endl;

    // Module 0 sends the first message
    if (bcastingNode) {
        VALUE val = VALUE(sizeVal,17);
        scheduleAndBroadcast(val);
    }
}


void Process::printRecho() {
    std::cout << KBLU << "--------- BEGIN Recho ---------" << KNRM << std::endl;
    for (std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1=this->Recho.begin(); it1!=this->Recho.end(); ++it1) {
        ProcSeq ps = it1->first;
        std::cout << KBLU << "[pid=" << ps.getPid() << ",seq=" << ps.getSeq() << "]" << KNRM << std::endl;
        std::map<VALUE,RechoEntry> m = it1->second;
        for (std::map<VALUE,RechoEntry>::iterator it2=m.begin(); it2!=m.end(); ++it2) {
            VALUE val = it2->first;
            bool lie     = Recho2lie(it2->second);
            bool sending = Recho2still(it2->second);
            PIDS full    = Recho2full(it2->second);
            Aggregate l  = Recho2aggr(it2->second);
            std::cout << KBLU << "  val=" << val << ",lie?=" << lie << ",sending?=" << sending << ",#full=" << full.size() << ",#signs=" << l.numSigners() << KNRM << std::endl;
            //l.print();
        }
    }
    std::cout << KBLU << "--------- END Recho ---------" << KNRM << std::endl;
}


void Process::printRdeliver() {
    std::cout << KBLU << "--------- BEGIN Rdeliver ---------" << KNRM << std::endl;
    for (std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1=this->Rdeliver.begin(); it1!=this->Rdeliver.end(); ++it1) {
        ProcSeq ps = it1->first;
        std::cout << KBLU << "[pid=" << ps.getPid() << ",seq=" << ps.getSeq() << "]" << KNRM << std::endl;
        std::map<VALUE,RdeliverEntry> m = it1->second;
        for (std::map<VALUE,RdeliverEntry>::iterator it2=m.begin(); it2!=m.end(); ++it2) {
            VALUE val   = it2->first;
            bool tout   = Rdeliver2tout(it2->second);
            PIDS full   = Rdeliver2full(it2->second);
            Aggregate l = Rdeliver2aggr(it2->second);
            std::cout << KBLU << "  val=" << val << ",timed-out?=" << tout << ",#full=" << full.size() << ",#signs=" << l.numSigners() << KNRM << std::endl;
            //l.print();
        }
    }
    std::cout << KBLU << "--------- END Rdeliver ---------" << KNRM << std::endl;
}


// countPassives will be meaningless if 0 dies before everyone had time to increment countCrashes
void Process::finish() {
    if (DEBUG) { std::cout << KBLU << getTag() << "finishing" << KNRM << std::endl; }

    // // Cancelling all scheduled messages
    // cFutureEventSet * events = cSimulation::getActiveSimulation()->getFES();
    // int me = 0;
    // int i = 0;
    // while (i < events->getLength()) {
    //    cEvent * event = events->get(i);
    //    if (event && event->isMessage() && ((cMessage *)event)->isSelfMessage()) {
    //      me++;;
    //      cModule *mod = ((cMessage *)event)->getSenderModule();
    //      if (mod && mod->getIndex() == this->selfid) {
    //        //sender = mod->getIndex();
    //        if (DEBUG0) { std::cout << KBLU << getTag() << "id:" << mod->getIndex() << KNRM << std::endl; }
    //        cancelAndDelete((cMessage *)event);
    //      }  else { i++; }
    //    } else { i++; }
    // }
    // if (DEBUG0) { std::cout << KBLU << getTag() << "clearing events (" << events->getLength() << "," << me << ")" << KNRM << std::endl; }
    // //events->clear();
    // if (DEBUG0) { std::cout << KBLU << getTag() << "cleared events" << KNRM << std::endl; }

    // We delete the channelTimers
    if (CLEAR) {
        if (DEBUG) { std::cout << KBLU << getTag() << "cleaning channel timers" << KNRM << std::endl; }
        for (int i = 0; i < nGates; i++) {
          if (DEBUG) { std::cout << KBLU << getTag() << "  - cleaning channel timer (id=" << channelTimers[i]->getId() << ")" << i << KNRM << std::endl; }
          //take(channelTimers[i]);
          drop(channelTimers[i]);
          if (DEBUG) { std::cout << KBLU << getTag() << "  + deleting channel timer " << i << KNRM << std::endl; }
          delete(channelTimers[i]);
          if (DEBUG) { std::cout << KBLU << getTag() << "  + cleaned channel timer " << i << KNRM << std::endl; }
        }
        if (DEBUG) { std::cout << KBLU << getTag() << "  - deleting channel timer array" << KNRM << std::endl; }
        delete[] channelTimers;
        if (DEBUG) { std::cout << KBLU << getTag() << "  + deleted channel timer array" << KNRM << std::endl; }
    }

    // we delete the outQueues
    if (CLEAR) {
        if (DEBUG) { std::cout << KBLU << getTag() << "cleaning queue" << KNRM << std::endl; }
        for (int i = 0; i < nGates; i++) {
          //int i = this->selfid;
          outQueues[i].clear();
        }
        if (DEBUG) { std::cout << KBLU << getTag() << "  - deleting queue" << KNRM << std::endl; }
        delete[] outQueues;
        if (DEBUG) { std::cout << KBLU << getTag() << "cleaned queue" << KNRM << std::endl; }
    }

    // countFinished++;
    // if (countFinished == nProcesses) {
    //   if (DEBUG0) { std::cout << KBLU << getTag() << "last clean" << KNRM << std::endl; }
    //   delete[] channelTimers;
    //   delete[] outQueues;
    // }

#ifdef KK_BLS
    if (DEBUG) std::cout << KBLU << getTag() << "cleaning BLS stuff" << KNRM << std::endl;
    KF.clearBls();
    if (DEBUG) std::cout << KBLU << getTag() << "cleaned BLS stuff" << KNRM << std::endl;
#endif


    if (selfid < nProcesses - numByz) {
        numFinish++;

        if (numFinish == nProcesses - numByz) {
            //std::cout << KBLU << getTag() << "printing stats" << KNRM << std::endl;
            // print the stats
            std::string s = passiveOutput;
            std::ofstream f;
            f.open(s, std::ofstream::out | std::ofstream::app);
            if (countPassives != 0) {
                f << countPassives << endl;
            } else {
                if (countDelivers < nProcesses - numByz) {
                    f << "9999" << endl;
                } else {
                    f << "0" << endl;
                }
            }
            f.close();

            s = passiveOutput + ".2f1"; //"stats/file";
            f.open(s, std::ofstream::out | std::ofstream::app);
            if (countDelivers >= quorumSize) {
                f << "1" << endl;
            } else {
                f << "0" << endl;
            }
            f.close();

            s = passiveOutput + ".outbdw";
            f.open(s, std::ofstream::out | std::ofstream::app);
            double avgbdw = 0.0;
            for (int i = 0; i < nProcesses - numByz; i++) {
                avgbdw += outBdwTotal[i];
            }
            avgbdw /= (nProcesses - numByz);
            f << avgbdw << endl;
            f.close();

            s = passiveOutput + ".msgs";
            f.open(s, std::ofstream::out | std::ofstream::app);
            int numMsgs = 0;
            for (int i = 0; i < nProcesses - numByz; i++) {
                numMsgs += stats[i].getNumSent();
                //std::cout << KBBLU << getTag() << "#SIGNS=" << stats[i].getNumSent() << KNRM << std::endl;
            }
            numMsgs /= (nProcesses - numByz);
            f << numMsgs << endl;
            f.close();

            double maxCrypto = 0.0;
            for (int i = 0; i < nProcesses; i++) {
                //std::cout << i << " : crypto time (microsec) = " << stats[i] << endl;
                if (maxCrypto < stats[i].getCryptoTime()) {
                    maxCrypto = stats[i].getCryptoTime();
                }
                if (DEBUG5) {
                    std::cout << KBBLU << getTag()
                            << " crypto time (microsec) = " << stats[i] << KNRM
                            << std::endl;
                }
                if (DEBUG9) {
                    std::cout << KBBLU << getTag() << " stats:"
                            << stats[i].to_string() << KNRM << std::endl;
                }
                if (DEBUG8) {
                    std::cout << KBBLU << getTag() << " bandwidth:"
                            << outBdwTotal[i] << KNRM << std::endl;
                }
            }

            double maxCryptoDeliver = 0.0;
            double secondMaxCryptoDeliver = 0.0;
            // WARNING: due to issues with the EC crypto library we're using, for one node (typically 0)
            // we get very high crypto numbers so we instead only consider the second largest
            for (int i = 0; i < nProcesses; i++) {
                if (cryptoTimesDeliver[i] > secondMaxCryptoDeliver) {
                  if (cryptoTimesDeliver[i] > maxCryptoDeliver) {
                    secondMaxCryptoDeliver = maxCryptoDeliver;
                    maxCryptoDeliver = cryptoTimesDeliver[i];
                  } else {
                    secondMaxCryptoDeliver = cryptoTimesDeliver[i];
                  }
                }
            }
            maxCryptoDeliver = secondMaxCryptoDeliver;

            //double totaldurationms = (timeToDeliver.dbl() * 1000 * 1000 + maxCryptoDeliver) / 1000.0;
            //std::cout << "Max crypto time (microsec) = " << maxCrypto << endl;
            //std::cout << "Total duration (ms) = " << totaldurationms << endl;

            if (countDelivers >= quorumSize) {
                s = durationOutput;
                std::ofstream f2;
                f2.open(s, std::ofstream::out | std::ofstream::app);
                f2 << timeToDeliver.dbl() * 1000 * 1000 << " " << maxCrypto
                        << " " << maxCryptoDeliver << " "
                        << simTime().dbl() * 1000 * 1000 << endl;
                f2.close();
            }
            //std::cout << KBLU << getTag() << "cleaning up stats stuff" << KNRM << std::endl;

            std::cout << stats->to_string() << std::endl;

            delete[] stats;
            delete[] cryptoTimesDeliver;
            delete[] outBdwTotal;

            //std::cout << KBLU << getTag() << "done!" << KNRM << std::endl;

//        std::cout << selfid << " crypto " << cryptoTimes[selfid] << " microseconds" << endl;
//        std::cout << "max crypto time = " << maxCrypto << endl;
//        double t = simTime().dbl() * 1000 * 1000; // in microseconds
//        std::cout << "end sim time " << t << endl;
//        double nrounds = t*1000.0 / D;
        }
    }

    // Print stats
    std::string sto = statsOutput;
    std::ofstream fsto;
    fsto.open(sto, std::ofstream::out | std::ofstream::app);
    //fsto << stats[selfid].to_string() << endl;
    fsto << cryptoTimesDeliver[selfid] << endl;
    fsto.close();

    if (DEBUG) { std::cout << KBLU << getTag() << "finished!" << KNRM << std::endl; }
}


void Process::becomePassive() {
    if (DEBUG0) { std::cout << KBBLU << getTag() << "BECOMING PASSIVE" << KNRM << std::endl; }

    // Then we have to become passive
    if (status == STATUS_ACTIVE) { countPassives++; }
    std::cout << "#PASSIVES:" << countPassives << endl;
    status = STATUS_PASSIVE;
    someActivity = false;

    if (switch_recovery) {
        // Scheduling a message to try to become active again
        Message msg(HDR_RECOVER);
        SimTime st = simTime();
        st = st + (((double) (PD * D)) / st.getScale());
        if (DEBUG11) { std::cout << KBLU << getTag() << "scheduling to try to become active at time " << st << " (scale:" << st.getScale() << ")" << KNRM << std::endl; }
        scheduleAt(st,msg.to_broadcast());
        if (DEBUG11) { std::cout << KBLU << getTag() << "scheduled message" << KNRM << std::endl; }
    }
}


// We cancel HDR_ACTIVE message if we fail to be timely while trying to recover
// Those message are there as a trigger to become active once we've been trying to
// recover for long enough
void Process::cancelActiveMessage() {
    if (activeMsg) { cancelEvent(activeMsg); }
}


void Process::enterPassiveMode(int n, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, unsigned int nsig) {
    if (DEBUG0) { std::cout << KBRED << getTag() << " entering PASSIVE mode (" << n << "," << status2string(status) << "):"
                            << " didn't collect enough messages for (pid=" << pid << ",seq=" << seq << ",val=" << val << "),"
                            << " only " << nsig
                            << " out of " << quorumSize
                            << KNRM << std::endl; }
    //printRecho();

    switch (status) {

    case STATUS_ACTIVE: {
        becomePassive();
        break;
    }

    case STATUS_PASSIVE: {
        // Then we don't do anything
        // There's a HDR_RECOVERING message scheduled - we could re-schedule it
        break;
    }

    case STATUS_RECOVERING: {
        // We're trying to recover, and we failed again to be timely, so we start the
        // passive process over again

        // We have to cancel the scheduled HDR_ACTIVE message
        cancelActiveMessage();

        // ...and we have to become passive again
        becomePassive();

        break;
    }

    }
}


void Process::triggerTimeoutBroadcast(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    if (it1 != this->Recho.end()) {

        if (DEBUG) { std::cout << KBLU << "found a corresponding broadcast entry" << KNRM << std::endl; }

        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            if (DEBUG) { std::cout << KBLU << "found a corresponding broadcast sub-entry" << KNRM << std::endl; }
            //bool lie     = std::get<0>(it2->second);
            //bool sending = std::get<1>(it2->second);
            Aggregate aggr = Recho2aggr(it2->second);

            if (aggr.numSigners() < quorumSize) {

                //if (DEBUG0) { std::cout << KBLU << getTag() << "entering passive mode (" << 1 << ")" << KNRM << std::endl; }
                enterPassiveMode(1,pid,seq,val,aggr.numSigners());
                //if (DEBUG0) { std::cout << KBLU << getTag() << "entered passive mode (" << 1 << ")" << KNRM << std::endl; }

            } else { someActivity = true; }
        }
    }
}


void Process::triggerTimeoutEcho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    if (it1 != this->Recho.end()) {

        if (DEBUG) { std::cout << KBLU << "found a corresponding echo entry" << KNRM << std::endl; }
        ProcSeq ps1 = it1->first;
        if (DEBUG) { std::cout << KBLU << "entry for " << ps1.getPid() << KNRM << std::endl; }

        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            if (DEBUG) { std::cout << KBLU << "found a corresponding echo sub-entry" << KNRM << std::endl; }
            // 'lie' is true if a lie has been discovered
            bool lie = Recho2lie(it2->second);
            // 'sending' is true if we're still echoing
            //bool sending = std::get<1>(it2->second);
            Aggregate signs = Recho2aggr(it2->second);

            if (signs.numSigners() < quorumSize) {

                if (!lie) { // no lie has been discovered

                    //if (DEBUG0) { std::cout << KBLU << getTag() << "entering passive mode (" << 2 << ")" << KNRM << std::endl; }
                    enterPassiveMode(2,pid,seq,val,signs.numSigners());
                    //if (DEBUG0) { std::cout << KBLU << getTag() << "entered passive mode (" << 2 << ")" << KNRM << std::endl; }

                }
            } else { someActivity = true; }
        }
    }
}


void Process::garbageCollectUpTo(PROCESS_ID pid, SEQUENCE_NUM seq, SEQUENCE_NUM h) {
    if (DEBUG) { std::cout << KBLU << "trying to garbage collect between " << h << " and " << seq << KNRM << std::endl; }
    // we keep trying to remove entries from h to seq as long as we can remove some
    // if we cannot remove an entry we stop
    bool keepGoing = true;
    for (int i = h; i <= seq && keepGoing; i++) {
        ProcSeq ps(pid,i);
        std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

        if (it1 != this->Rdeliver.end()) {
            // found a corresponding deliver entry

            bool b = true;
            std::map<VALUE,RdeliverEntry> m = it1->second;

            for (std::map<VALUE,RdeliverEntry>::iterator it2 = m.begin(); it2 != m.end(); it2++) {
                bool tout = Rdeliver2tout(it2->second);
                // if not timed-out yet (i.e., !tout), then we won't garbage collect this entry (i.e., pid/seq)
                if (!tout) { b = false; break; }
            }

            if (b) {
                // if b is true then all the entries in m have timed-out
                if (DEBUG) std::cout << KBBLU << getTag() << "garbage collecting (" << pid << "," << seq << ")" << KNRM << std::endl;
                Rdeliver.erase(ps);
                Recho.erase(ps);
                highest[pid]=i+1;
                if (DEBUG0) std::cout << KBBLU << getTag() << "garbage collected (" << pid << "," << seq << ")" << KNRM << std::endl;
            } else { keepGoing = false; }
        }
    }
}


void Process::garbageCollect(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    if (GC) {
        std::map<PROCESS_ID,SEQUENCE_NUM>::iterator itH = this->highest.find(pid);
        if (itH != this->highest.end()) {
            // found a corresponding entry
            SEQUENCE_NUM h = itH->second;
            if (h <= seq) {
                // we can try to garbage collect form h up to seq
                Process:garbageCollectUpTo(pid,seq,h);
            }
        } // else didn't find a corresponding entry, which shouldn't happen
    }
}


void Process::triggerTimeoutDeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    if (it1 != this->Rdeliver.end()) {

        if (DEBUG) { std::cout << KBLU << "found a corresponding deliver entry" << KNRM << std::endl; }

        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {
            bool tout       = Rdeliver2tout(it2->second);
            PIDS full       = Rdeliver2full(it2->second);
            PIDS tosend     = Rdeliver2tosend(it2->second);
            Aggregate signs = Rdeliver2aggr(it2->second);

            if (signs.numSigners() < quorumSize) {

                //if (DEBUG0) { std::cout << KBLU << getTag() << "entering passive mode (" << 3 << ")" << KNRM << std::endl; }
                enterPassiveMode(3,pid,seq,val,signs.numSigners());
                //if (DEBUG0) { std::cout << KBLU << getTag() << "entered passive mode (" << 3 << ")" << KNRM << std::endl; }

            } else {

                someActivity = true;
                m[val]=std::make_tuple(true,full,tosend,signs); // true means that we have now timed-out for this pid/seq/val
                this->Rdeliver[ps]=m;
                garbageCollect(pid,seq,val);

            }
        }
    }
}


/*void Process::triggerTimeout(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode) {
  // This fails in the thread but not outside.  Why?  Some race?
  // Also, it only fails when going inside Recho, but not when iterating through Recho...
  //checkRecho();

  sleepForTime(timeout);

  switch (mode) {

  case MODE_BROADCAST:
    triggerTimeoutBroadcast(pid, seq, val);
    break;

  case MODE_ECHO:
    triggerTimeoutEcho(pid, seq, val);
    break;

  case MODE_DELIVER:
    triggerTimeoutDeliver(pid, seq, val);
    break;

  }
}*/


void Process::handleTimeout(PID sender, Message timeout) {
    PROCESS_ID pid   = timeout.getPid();
    SEQUENCE_NUM seq = timeout.getSeq();
    VALUE val        = timeout.getVal();
    MODE mode        = timeout.getMode();

    if (DEBUG) { std::cout << KLBLU << ">>> " << this->selfid << "-handling timeout (" << pid << ", " << seq << ", " << val << ")" << KNRM << std::endl; }

    switch (mode) {

    case MODE_BROADCAST:
        triggerTimeoutBroadcast(pid, seq, val);
        break;

    case MODE_ECHO:
        triggerTimeoutEcho(pid, seq, val);
        break;

    case MODE_DELIVER:
        triggerTimeoutDeliver(pid, seq, val);
        break;

    }
}


std::string pids2string (PIDS pids) {
    std::string s = "-";
    for (std::set<PROCESS_ID>::iterator it = pids.begin(); it != pids.end(); ++it) {
        s += std::to_string((PID)*it) + "-";
    }
    return s;
}


std::string pids2string (PIDL pids) {
    std::string s = "-";
    for (std::list<PROCESS_ID>::iterator it = pids.begin(); it != pids.end(); ++it) {
        s += std::to_string((PID)*it) + "-";
    }
    return s;
}


std::string pids2string (PIDV pids) {
    std::string s = "-";
    for (std::vector<PROCESS_ID>::iterator it = pids.begin(); it != pids.end(); ++it) {
        s += std::to_string((PID)*it) + "-";
    }
    return s;
}


RechoEntry Process::updateRechoEntryTosend(RechoEntry e, PIDS tosend) {
    bool lie        = Recho2lie(e);
    bool still      = Recho2still(e);
    PIDS full       = Recho2full(e);
    //PIDS tosend     = Recho2tosend(e);
    Aggregate signs = Recho2aggr(e);
    return mkRechoEntry(lie,still,full,tosend,signs);
}


RdeliverEntry Process::updateRdeliverEntryTosend(RdeliverEntry e, PIDS tosend) {
    bool tout       = Rdeliver2tout(e);
    PIDS full       = Rdeliver2full(e);
    //PIDS tosend     = Rdeliver2tosend(e);
    Aggregate signs = Rdeliver2aggr(e);
    return mkRdeliverEntry(tout,full,tosend,signs);
}


void Process::updateRechoTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, PIDS tosend) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    Aggregate a;

    if (it1 != this->Recho.end()) {
        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {
            m[val]=updateRechoEntryTosend(it2->second,tosend);
            it1->second=m;
        }
        else { throw 0; }
    } else { throw 0; }
}


void Process::updateRdeliverTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, PIDS tosend) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    Aggregate a;

    if (it1 != this->Rdeliver.end()) {
        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {
            m[val]=updateRdeliverEntryTosend(it2->second,tosend);
            it1->second=m;
        }
        else { throw 0; }
    } else { throw 0; }
}


PIDS Process::selectRechoTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    Aggregate a;

    if (it1 != this->Recho.end()) {
        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) { return Recho2tosend(it2->second); }
        else { throw 0; }
    } else { throw 0; }
}


PIDS Process::selectRdeliverTosend(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    Aggregate a;

    if (it1 != this->Rdeliver.end()) {
        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) { return Rdeliver2tosend(it2->second); }
        else { throw 0; }
    } else { throw 0; }
}


std::vector<PROCESS_ID> Process::selectRecipients_random(PIDS full, Message msg) {
    std::vector<PROCESS_ID> all;
    for (int i = 0; i <= nGates; i++) {
        //if (DEBUG) { std::cout << KBLU << getTag() << " adding? " << i << KNRM << std::endl; }
        // We only add i to all if it's not ourself (we don't send to ourself) and if we don't know that
        // i has already received enough message (i.e., i is not in full)
        // For some reason, this optimization was removed in this commit:
        // 794961d14154335f703ce6f4e3d6439302864d49 (2019-03-13 19:53:03)
        if (i != this->selfid && full.find(i) == full.end()) { all.push_back(i); }
    }
    std::random_shuffle(all.begin(), all.end());

    // we keep the first numRand values
    all.resize(numRand);

    // we finally return the vector
    return all;
}


std::vector<PROCESS_ID> Process::selectRecipients_rounds(PIDS full, Message msg) {
    HEADER       hdr  = msg.getHeader();
    PROCESS_ID   pid  = msg.getPid();
    SEQUENCE_NUM seq  = msg.getSeq();
    VALUE        val  = msg.getVal();
    MODE         mode = msg.getMode();

    std::vector<PROCESS_ID> all;

    PIDS tosend;
    if (mode == MODE_BROADCAST || mode == MODE_ECHO) { tosend = selectRechoTosend(pid,seq,val); }
    else { tosend = selectRdeliverTosend(pid,seq,val); }
    unsigned int tryInst = 0;
    unsigned int numFound = 0;
    // We're allowed to run these loops twice:
    //  - once using the 'tosend' list
    //  - and a second time using all the nodes
    while (numFound < numRand && tryInst < 2) {
        PIDS::iterator it = tosend.begin();
        while (numFound < numRand && it != tosend.end()) {
            PROCESS_ID i = *it;
            PIDS::iterator tmp = it;
            it++;
            tosend.erase(tmp);
            // if i is not us, not in the 'full' list and not already in 'all' then we add it to 'all'
            if (i != this->selfid && full.find(i) == full.end() && std::find(all.begin(), all.end(), i) == all.end()) {
                numFound++;
                all.push_back(i);
            }
        }
        // if we went through the whole 'tosend' list and still haven't found enough elements to add
        // then we loop back and put back all the nodes (minus 'full' and 'selfid') to 'tosend'
        // NOTE: Whenever we loop back, we could randomize the set
        if (numFound < numRand) {
            tryInst++;
            tosend = others(full);
        }
    }
    if (mode == MODE_BROADCAST || mode == MODE_ECHO) { updateRechoTosend(pid,seq,val,tosend); }
    else { updateRdeliverTosend(pid,seq,val,tosend); }
    return all;
}


int Process::id2channel(int pid) {
    if (pid < selfid) { return pid; } else { return (pid - 1); }
}


void Process::printIf(PIDV all, Message msg) {
    if (std::find(all.begin(), all.end(), 0) != all.end()) {
        if (DEBUG0) { std::cout << KBLU << getTag() << "sending message (hdr=" << header2string(msg.getHeader()) << ",pid=" << msg.getPid() << ",seq=" << msg.getSeq() << ",val=" << msg.getVal().to_string() << ") to:" << pids2string(all) << KNRM << std::endl; }
    }
}


int Process::getLastRound() {
    SimTime curTime  = simTime();
    int scale        = curTime.getScale();
    //std::cout << "scale:" << scale << std::endl;
    int lastRound    = (int)(floor(((curTime*scale)/D).dbl()));
    return lastRound;
}


// We send the message to 'numRand' random processes
void Process::sendMsgNotLost(PIDS full, Message msg) {

    //    if (DEBUG2) { std::cout << KBLU << getTag() <<  "sending message (" << mode2string(msg.getMode()) <<  ") to " << l.size() << " nodes: " << pidl2string(l) << "; removed: " << pids2string(full) << KNRM << std::endl; }

    PIDV all;
    if (switch_rotating_send) {
        all = selectRecipients_rounds(full, msg);
    } else {
        all = selectRecipients_random(full, msg);
    }

    //printIf(all,msg);

    int ndestgates = (this->numRand < all.size()) ? this->numRand : all.size();
    for (int i = 0; i < ndestgates; i++) {
        PROCESS_ID pid = all[i];
        int channelId = id2channel(pid);
        //        if (DEBUG) {std::cout << KBLU << getTag() << "sending message to " << id << " through " << channelId << KNRM << std::endl;}
        //if (DEBUG0) { std::cout << KBLU << getTag() << "sending message through " << channelId << KNRM << std::endl; }

        // TODO: send the message with a random delay uniformly distributed between 0 and d
        if (gate("gate$o", channelId)->isConnected()) {
            //if (DEBUG0) { std::cout << KBLU << getTag() << "connected" << KNRM << std::endl; }
            BroadcastMsg *m = msg.to_broadcast();
            int size = msg.size() * 8;
            m->setBitLength(size);
            outBdwTotal[selfid] += size;
            //if (DEBUG8) { std::cout << KBBLU << getTag() << " bandwidth:" << outBdwTotal[selfid] << KNRM << std::endl; }

            SimTime curTime  = simTime();
            int scale        = curTime.getScale();
            //std::cout << "scale:" << scale << std::endl;
            int lastRound    = (int)(floor(((curTime*scale)/D).dbl()));
            int nextRound    = lastRound+1;
            m->setRound(nextRound);

            if (DEBUG) { std::cout << KBLU << getTag() << "message-size=" << size << KNRM << std::endl; }
            if (!gate("gate$o", channelId)->getTransmissionChannel()->isBusy()) { // channel is not busy
                outBdwVector.record(0.0);
                outBdwVector.record(gate("gate$o", channelId)->getTransmissionChannel()->getNominalDatarate());
                if (DEBUG11) { if (pid == 0) { std::cout << KBLU << getTag() << "sending message (id=" << m->getId() << ")" << KNRM << std::endl;  } }
                //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 1" << KNRM << std::endl; } }
                stats[selfid].incrementNumNonDelayed();

                // In RT-ByzCast mode we send messages at the next round
                // Otherwise, we send it right away
                if (rtByzCastMode) {
                    //if (DEBUG12) { std::cout << KBLU << getTag() << "RT-ByzCast mode: delaying message" << KNRM << std::endl; }
                    SimTime nextTime = ((double)(nextRound * D)) / scale;
                    SimTime delay    = nextTime - curTime;
                    if (DEBUG) {
                        std::cout << KBLU << getTag() << "curTime=" << curTime << ";nextTime=" << nextTime << ";lastRound=" << lastRound << KNRM << std::endl;
                        std::cout << delay << endl;
                    }
                    //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 2" << KNRM << std::endl; } }
                    stats[selfid].incrementNumSent();
                    sendDelayed(m, delay, "gate$o", channelId);
                    //send(m, "gate$o", channelId);
                } else {
                    //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 3" << KNRM << std::endl; } }
                    stats[selfid].incrementNumSent();
                    send(m, "gate$o", channelId);
                }

                if (!channelTimers[channelId]->isScheduled()) { // WTF! Necessary otherwise passive
                    scheduleAt(gate("gate$o", channelId)->getTransmissionChannel()->getTransmissionFinishTime(),
                               channelTimers[channelId]);
                }
            } else {
                outBdwVector.record(gate("gate$o", channelId)->getTransmissionChannel()->getNominalDatarate());
                if (DEBUG) { std::cout << KBLU << getTag() << "busy, will send later" << KNRM << std::endl; }
                if (DEBUG) { if (pid == 0) { std::cout << KBLU << getTag() << "sending delayed" << KNRM << std::endl;  } }
                //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 4" << KNRM << std::endl; } }
                stats[selfid].incrementNumDelayed();
                outQueues[channelId].insert(m);
            }
        } else {
            //if (DEBUG) { std::cout << KBRED << getTag() << "couldn't send to " << id << ": not connected" << KNRM << std::endl; }
            if (DEBUG) { std::cout << KBRED << getTag() << "couldn't send through " << channelId << ": not connected" << KNRM << std::endl; }
        }
    }
}


void Process::sendMsg(PIDS full, Message msg) {
    if (!switch_loss_send || rand() % 100 < (100-probaLosses)) {
        sendMsgNotLost(full,msg);
    }
}


bool Process::stillEchoing(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    if (it1 != this->Recho.end()) {

        if (DEBUG) { std::cout << KBLU << "found a corresponding echo entry" << KNRM << std::endl; }

        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            // std::cout << KBLU << "found a corresponding echo sub-entry" << KNRM << std::endl;
            return Recho2still(it2->second);

        } else {

            // std::cout << KBLU << "didn't find a corresponding echo sub-entry" << KNRM << std::endl;
            return true;

        }

    } else {

        // std::cout << KBLU << "didn't find a corresponding echo entry" << KNRM << std::endl;
        return true;

    }
}


// This is called in separate threads because of the sleep
/*void Process::tDiffuse(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode) {
  if (DEBUG) { std::cout << KBLU << "diffusing " << (timeout / D) << " times (timeout: " << timeout << ",D:" << D << ")" << KNRM << std::endl; }

  for (unsigned int i = 0; i < timeout / D; i ++) {

    if (mode == MODE_BROADCAST) {

      Message bcast(HDR_BROADCAST,pid,seq,val,{},signs);
      if (DEBUG) { std::cout << KBLU << "diffusing broadcast" << KNRM << std::endl; }
      sendMsg(bcast);

    } else if (mode == MODE_ECHO) {

      if (stillEchoing(pid,seq,val)) {

    Message echo(HDR_ECHO,pid,seq,val,{},signs);
    if (DEBUG) { std::cout << KBLU << "diffusing echo" << KNRM << std::endl; }
    sendMsg(echo);

      }

    } else if (mode == MODE_DELIVER) {

      Message del(HDR_DELIVER,pid,seq,val,esigns,signs);
      if (DEBUG) { std::cout << KBLU << "diffusing deliver" << KNRM << std::endl; }
      sendMsg(del);
    }

    sleepForTime(D);
  }
}*/


PIDS Process::getFullInRecho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    if (it1 != this->Recho.end()) {
        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) { return Recho2full(it2->second); }
        else { return {}; }
    } else { return {}; }
}


Aggregate Process::getSignsInRecho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    Aggregate a;

    if (it1 != this->Recho.end()) {
        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) { return Recho2aggr(it2->second); }
        else { return a; }
    } else { return a; }
}


PIDS Process::getFullInRdeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    if (it1 != this->Rdeliver.end()) {
        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) { return Rdeliver2full(it2->second); }
        else { return {}; }
    } else { return {}; }
}


Aggregate Process::getSignsInRdeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    Aggregate a;

    if (it1 != this->Rdeliver.end()) {
        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) { return Rdeliver2aggr(it2->second); }
        else { return a; }
    } else { return a; }
}


void Process::handleDiffuse(PID sender, Message diffuse) {
    PROCESS_ID pid   = diffuse.getPid();
    SEQUENCE_NUM seq = diffuse.getSeq();
    VALUE val        = diffuse.getVal();
    Aggregate esigns = diffuse.getEsign();
    Aggregate signs  = diffuse.getSign();
    MODE mode        = diffuse.getMode();
    int inst         = diffuse.getInst();

    if (DEBUG) { std::cout << KLBLU << getTag() << ">>> handling diffuse (" << pid << ", " << seq << ", " << val << ")" << KNRM << std::endl; }

    switch(mode) {

    case MODE_BROADCAST: {

        PIDS full = {};
        Message bcast(HDR_BROADCAST,pid,seq,val,{},signs,mode);
        if (DEBUG) { std::cout << KBLU << getTag() << "diffusing broadcast" << KNRM << std::endl; }
        sendMsg(full,bcast);
        break;

    }

    case MODE_ECHO: {

        if (stillEchoing(pid,seq,val)) {
            if (DEBUG) { std::cout << KBLU << getTag() << "still echoing" << KNRM << std::endl; }
            PIDS full = {};
            if (opt_switch_full) {
                full = getFullInRecho(pid,seq,val);
            }
            if (opt_switch_renew) {
                // TOCHECK: check this with the guys
                // TODO: use the new signs
                signs = getSignsInRecho(pid,seq,val);
                // ---
            }
            Message echo(HDR_ECHO,pid,seq,val,{},signs,mode);
            if (DEBUG) { std::cout << KBLU << getTag() << "diffusing echo" << KNRM << std::endl; }
            sendMsg(full,echo);
        }
        break;

    }

    case MODE_DELIVER: {

        PIDS full = {};
        if (opt_switch_full) {
            full = getFullInRdeliver(pid,seq,val);
        }
        if (opt_switch_renew) {
            // TOCHECK: check this with the guys
            // TODO: use the new signs
            //   We can only do that if we don't sign the echo signatures when generating the deliver signatures...
            if (DEBUG2) { std::cout << KBLU << getTag() << "old deliver:" << signs.numSigners() << KNRM << std::endl; }
            signs = getSignsInRdeliver(pid,seq,val);
            if (DEBUG2) { std::cout << KBLU << getTag() << "new deliver:" << signs.numSigners() << KNRM << std::endl; }
            // ---
        }
        Message del(HDR_DELIVER,pid,seq,val,esigns,signs,mode);
        if (DEBUG) { std::cout << KBLU << getTag() << "diffusing deliver" << KNRM << std::endl; }
        sendMsg(full,del);
        checkEndSimulation(pid,seq,mode,inst);
        break;

    }
    }
}


// TODO
void Process::triggerDeliverIfActive(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    countDelivers++;
    if (countDelivers == quorumSize) {
        timeToDeliver = simTime();
    }
    //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 5" << KNRM << std::endl; } }
    cryptoTimesDeliver[selfid] = stats[selfid].getCryptoTime();
    if (DEBUG0) std::cout << KBGRN << getTag() << " *** DELIVERED(pid=" << pid << ",seq=" << seq << ",val=" << val << ") *** " << KNRM << std::endl;
    if (DEBUG5) { std::cout << KBGRN << getTag() << " crypto time (microsec) = " << stats[selfid] << KNRM << std::endl; }

    // When this switch is on, we stop the systems as soon as a quorum delivered
    if (switch_stop_as_soon_as_quorum_deliverd) {
      if (quorumSize <= countDelivers) {
        if (DEBUG13) { std::cout << KBMAG << getTag() << "stopping early" << KNRM << std::endl; }
        //callFinish();
        //endSimulation();
        endSimu=true;
      }
    }
}


void Process::triggerDeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    if (status == STATUS_ACTIVE) { triggerDeliverIfActive(pid,seq,val); }
}


// When we stop sending, it means that tDiffuse, will not send echos in the 'echo' case.
void Process::stopSendingEchos(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    if (it1 != this->Recho.end()) {

        if (DEBUG) { std::cout << KBLU << getTag() << "found a corresponding echo entry" << KNRM << std::endl; }

        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            if (DEBUG) { std::cout << KBLU << getTag() << "found a corresponding echo sub-entry" << KNRM << std::endl; }
            if (DEBUG) { std::cout << KBLU << getTag() << "stopping echoing for [pid=" << pid << ";seq=" << seq << ";val=" << val << "]" << KNRM << std::endl; }

            bool lie        = Recho2lie(it2->second);
            bool echoing    = false;
            PIDS full       = Recho2full(it2->second);
            PIDS tosend     = Recho2tosend(it2->second);
            Aggregate signs = Recho2aggr(it2->second);

            m[val]=mkRechoEntry(lie,echoing,full,tosend,signs);
            it1->second=m;
            //std::get<1>(it2->second)=false;
            //printRecho();

        } else {

            if (DEBUG) { std::cout << KBLU << getTag() << "didn't find a corresponding echo sub-entry" << KNRM << std::endl; }

        }

    } else {

        if (DEBUG) { std::cout << KBLU << getTag() << "didn't find a corresponding echo entry" << KNRM << std::endl; }

    }
}


void Process::checkEndSimulation(PROCESS_ID pid, SEQUENCE_NUM seq, MODE mode, int inst) {
    if (switch_recovery && switch_end_simu_delv) {
        // Once we're done delivering a message from a broadcaster pid, and that message is the last message broadcasted by pid
        if (mode == MODE_DELIVER && pid < numBcaster && seq == numBcast - 1 && inst == getNumRep()-1) {
            numFinishedBcaster++;
            if (DEBUG) { std::cout << KMAG << getTag() << "simulation done for " << pid << "; " << numFinishedBcaster << " out of " << numBcaster << KNRM << std::endl; }
            // We finish if we're done delivering the last message broadcasted by each broadcaster
            if (numFinishedBcaster == numBcaster) {
                if (DEBUG0) { std::cout << KMAG << getTag() << "ending simulation" << KNRM << std::endl; }
                endSimu = true;
                //callFinish(); // finish doesn't actually finish here...
                //deleteModule();
            }
        }
    }
}


// This is called in separate threads because of the sleep
void Process::tDiffuseLoop(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode) {
    if (DEBUG) { std::cout << KBLU << "scheduling the diffuse of " << mode2string(mode) << " " << (timeout / D) << " times (timeout: " << timeout << ",D:" << D << ")" << KNRM << std::endl; }

    int K = getNumRep();
    for (unsigned int i = 0; i < K; i ++) {
        Message msgDiffuse(HDR_DIFFUSE,pid,seq,val,esigns,signs,mode,i);
        SimTime st = simTime();
        st = st + (((double)(i*D)) / st.getScale());
        //SimTime delayDiffuse(i*D);
        if (DEBUG) { std::cout << KBLU << "scheduling diffuse(" << i << ") at time " << st << " (scale:" << st.getScale() << ")" << KNRM << std::endl; }
        scheduleAt(st,msgDiffuse.to_broadcast());
    }

    //checkEndSimulation(pid,seq,mode);
}


void Process::triggerDiffuse(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs, LOCTIME timeout, MODE mode) {
    // Scheduling internal diffuse messages
    tDiffuseLoop(pid,seq,val,esigns,signs,timeout,mode);

    // Scheduling internal timeout message
    Message msgTimeout(HDR_TIMEOUT,pid,seq,val,esigns,signs,mode);
    SimTime st = simTime();
    st = st + (((double) timeout) / st.getScale());
    if (DEBUG) { std::cout << KBLU << "scheduling timeout at time " << st << " (scale:" << st.getScale() << ")" << KNRM << std::endl; }
    scheduleAt(st,msgTimeout.to_broadcast());
}


void Process::deliverMessage(PID sender, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esigns, Aggregate signs) {
    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    if (it1 != this->Rdeliver.end()) {

        if (DEBUG) { std::cout << KBLU << "found a corresponding deliver entry" << KNRM << std::endl; }

        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {
            if (DEBUG) { std::cout << KBLU << "found a corresponding deliver entry" << KNRM << std::endl; }
        } else {

            if (DEBUG) { std::cout << KBLU << "entry not found" << KNRM << std::endl; }
            triggerDeliver(pid,seq,val);

            PIDS full = {};
            if (opt_switch_full) {
                if (signs.numSigners() >= quorumSize) {
                    if (DEBUG2) { std::cout << KBLU << getTag() << "full(D1):" << sender << KNRM << std::endl; }
                    full.insert(sender);
                } else {
                    if (DEBUG2) { std::cout << KBLU << getTag() << "not full(D1):" << signs.numSigners() << KNRM << std::endl; }
                }
            }

            // aggregate signatures: sign pid/seq/val/esigns and add the new signature to signs
            //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 6" << KNRM << std::endl; } }
            signs.aggregateSign(aggBound,KF,this->priv,this->selfid,PHASE_DELIVER,pid,seq,val,stats[selfid]);//,esigns);
            //printSigns(signs);

            // Create a deliver certificate
            std::map<VALUE,RdeliverEntry> m;
            bool tout   = false;
            PIDS tosend = others(full);
            m[val]=mkRdeliverEntry(tout,full,tosend,signs);
            this->Rdeliver[ProcSeq(pid,seq)]=m;
            //printRdeliver();

            // stop sending any Echo()
            stopSendingEchos(pid,seq,val);
        }

    } else {

        if (DEBUG) { std::cout << KBLU << "entry not found" << KNRM << std::endl; }
        triggerDeliver(pid,seq,val);

        PIDS full = {};
        if (opt_switch_full) {
            if (signs.numSigners() >= quorumSize) {
                if (DEBUG2) { std::cout << KBLU << getTag() << "full(D2):" << sender << KNRM << std::endl; }
                full.insert(sender);
            } else {
                if (DEBUG2) { std::cout << KBLU << getTag() << "not full(D2):" << signs.numSigners() << KNRM << std::endl; }
            }
        }

        // aggregate signatures: sign pid/seq/val/esigns and add the new signature to signs
        //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 7" << KNRM << std::endl; } }
        signs.aggregateSign(aggBound,KF,this->priv,this->selfid,PHASE_DELIVER,pid,seq,val,stats[selfid]);//,esigns);
        //printSigns(signs);

        // Create a deliver certificate
        std::map<VALUE,RdeliverEntry> m;
        bool tout   = false;
        PIDS tosend = others(full);
        m[val]=mkRdeliverEntry(tout,full,tosend,signs);
        this->Rdeliver[ProcSeq(pid,seq)]=m;
        //printRdeliver();

        // stop sending any Echo()
        stopSendingEchos(pid,seq,val);
    }

    // diffuse the deliver
    triggerDiffuse(pid,seq,val,esigns,signs,2 * this->timeout,MODE_DELIVER);
}


void Process::handleStart(PID sender, Message msg) {
    scheduleAndBroadcast(msg.getVal());
}


void Process::handleBroadcast(PID sender, Message bcast) {
    Aggregate    k; // empty aggregate
    PROCESS_ID   pid = bcast.getPid();
    SEQUENCE_NUM seq = bcast.getSeq();
    VALUE        val = bcast.getVal();
    Aggregate    sig = bcast.getSign();

    if (DEBUG1) { std::cout << KLBLU << getTag() << "<<< handling broadcast (" << pid << ", " << seq << ", " << val << ") >>>" << KNRM << std::endl; }

    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it = this->Recho.find(ps);

    if (it != this->Recho.end()) {
        if (DEBUG) { std::cout << KBLU << "skipping the broadcast because found a corresponding entry" << KNRM << std::endl; }
    } else {

        if (DEBUG) { std::cout << KBLU << "broadcast entry not found" << KNRM << std::endl; }

        // TODO: Execute proof-of-connectivity in piggyback mode

        // aggregate signatures
        if (DEBUG3) { std::cout << KGRN << selfid << ":aggregating-RCV-BCAST" << KNRM << std::endl; }
        //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 8" << KNRM << std::endl; } }
        sig.aggregateSign(aggBound,KF,this->priv,this->selfid,PHASE_ECHO,pid,seq,val,stats[selfid]);

        // Create an echo certificate
        std::map<VALUE,RechoEntry> m;
        // false means that no lie has been discovered so far
        bool lie    = false;
        bool still  = true;
        PIDS full   = {};
        PIDS tosend = others(full);
        m[val]=mkRechoEntry(lie,still,full,tosend,sig);
        this->Recho[ps]=m;

        //checkRecho();

        // Start diffusing the echo
        triggerDiffuse(pid,seq,val,k,sig,this->timeout,MODE_ECHO);
    }
}


void Process::handleEcho(PID sender, Message echo) {
    // QUESTION: Shouldn't we check here that the echo doesn't come from us?

    PROCESS_ID   pid = echo.getPid();
    SEQUENCE_NUM seq = echo.getSeq();
    VALUE        val = echo.getVal();
    Aggregate    sig = echo.getSign();

    if (DEBUG1) { std::cout << KLBLU << getTag() << "<<< handling echo (" << pid << ", " << seq << ", " << val << ") >>>" << KNRM << std::endl; }

    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    if (it1 != this->Recho.end()) {

        // We have entries for the pair pid/seq
        if (DEBUG) { std::cout << KBLU << "found a corresponding echo entry" << KNRM << std::endl; }
        //printRecho();

        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            if (DEBUG) { std::cout << KBLU << "found a corresponding echo sub-entry" << KNRM << std::endl; }

            bool lie        = Recho2lie(it2->second);
            bool echoing    = Recho2still(it2->second);
            PIDS full       = Recho2full(it2->second);
            PIDS tosend     = Recho2tosend(it2->second);
            Aggregate signs = Recho2aggr(it2->second);

            int oldSize = signs.numSigners();

            if (opt_switch_full) {
                // if sig contains more than 2f+1 replicas, we don't need to send to the sender of the echo anymore
                if (sig.numSigners() >= quorumSize) {
                    if (DEBUG2) { std::cout << KBLU << getTag() << "full(E1):" << sender << KNRM << std::endl; }
                    full.insert(sender);
                } else {
                    if (DEBUG2) { std::cout << KBLU << getTag() << "not full(E1):" << sig.numSigners() << KNRM << std::endl; }
                }
            }

            // TODO: Shouldn't our signature be in signs already?
            if (DEBUG3) {
                if (signs.containsSigner(selfid)) { std::cout << KBRED << getTag() << "IN" << KNRM << std::endl; }
                else { std::cout << KBRED << getTag() << "OUT" << KNRM << std::endl; }
            }

            // aggregate signatures
            if (DEBUG3) { std::cout << KGRN << selfid << ":aggregating-IN" << KNRM << std::endl; }
            //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 9" << KNRM << std::endl; } }
            signs.aggregateSign(aggBound,KF,this->priv,this->selfid,PHASE_ECHO,pid,seq,val,stats[selfid]);
            sig.aggregateWith(aggBound,KF,signs,stats[selfid]);
            int newSize = sig.numSigners();

            // Update the echo certificate
            m[val]=mkRechoEntry(lie,echoing,full,tosend,sig);
            it1->second=m;

            //printRecho();

            if (sig.numSigners() >= quorumSize && oldSize < quorumSize) { // i.e., for the 1st time
                if (DEBUG) { std::cout << KBBLU << "received enough echos to deliver (" << sig.numSigners() << ")" << KNRM << std::endl; }
                // got enough signatures to deliver
                Aggregate aggr;
                deliverMessage(sender,pid,seq,val,sig,aggr);
            }

        } else {

            // we haven't seen val before but we have entries for the pair pid/seq
            if (DEBUG) { std::cout << KBLU << "not found!" << KNRM << std::endl; }

            // aggregate signatures
            // TODO: why do we add our signature here?
            //sig.aggregateSign(this->priv,this->selfid,pid,seq,val);

            // TODO: for the 1st time.  Do we really have to check anything here?
            // Next time we receive pid/seq/val it will be in our state
            if (sig.numSigners() >= quorumSize) {
                // got enough signatures to deliver

                // garbage collect the entries for the other values (!= val)
                while (m.begin() != m.end()) { m.erase(m.begin()); }

                // Create the echo certificate for val
                bool lie     = true;
                bool echoing = true;
                PIDS full    = {};
                PIDS tosend  = others(full);
                if (opt_switch_full) { full.insert(sender); }
                m[val]=mkRechoEntry(lie,echoing,full,tosend,sig);
                it1->second=m;

                Aggregate aggr;
                deliverMessage(sender,pid,seq,val,sig,aggr);
            } else {
                // This updates all the entries to indicate that a lie has been discovered
                for (std::map<VALUE,RechoEntry>::iterator it = m.begin(); it != m.end(); ++it) {
                    bool lie        = true;
                    bool echoing    = Recho2still(it->second);
                    PIDS full       = Recho2full(it->second);
                    PIDS tosend     = Recho2tosend(it->second);
                    Aggregate signs = Recho2aggr(it->second);
                    m[it->first]=mkRechoEntry(lie,echoing,full,tosend,signs);
                }
                it1->second=m;
            }

        }

    } else {

        if (DEBUG) { std::cout << KBLU << "not found!" << KNRM << std::endl; }

        // TODO: Execute proof-of-connectivity in piggyback mode

        // aggregate signatures
        if (DEBUG3) { std::cout << KGRN << selfid << ":aggregating-OUT" << KNRM << std::endl; }
        //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 10" << KNRM << std::endl; } }
        sig.aggregateSign(aggBound,KF,this->priv,this->selfid,PHASE_ECHO,pid,seq,val,stats[selfid]);

        // lie=false means that no lie has been discovered so far
        // echoing=true means that we're still echoing
        bool lie     = false;
        bool echoing = true;
        PIDS full    = {};
        PIDS tosend  = others(full);
        if (opt_switch_full) {
            if (sig.numSigners() >= quorumSize) {
                if (DEBUG2) { std::cout << KBLU << getTag() << "full(E2):" << sender << KNRM << std::endl; }
                full.insert(sender);
            } else {
                if (DEBUG2) { std::cout << KBLU << getTag() << "not full(E2):" << sig.numSigners() << KNRM << std::endl; }
            }
        }

        // Create an echo certificate
        std::map<VALUE,RechoEntry> m;
        m[val]=mkRechoEntry(lie,echoing,full,tosend,sig);
        this->Recho[ps]=m;

        if (sig.numSigners() < quorumSize) {
            // Start diffusing the echo
            Aggregate k; // empty aggregate
            triggerDiffuse(pid,seq,val,k,sig,this->timeout,MODE_ECHO);
        } else {
            // got enough signatures to deliver
            Aggregate aggr;
            deliverMessage(sender,pid,seq,val,sig,aggr);
        }
    }
}


void Process::handleDeliver(PID sender, Message del) {
    // TODO: QUESTION: Shouldn't we check here that the deliver doesn't come from us?

    PROCESS_ID   pid  = del.getPid();
    SEQUENCE_NUM seq  = del.getSeq();
    VALUE        val  = del.getVal();
    Aggregate    esig = del.getEsign();
    Aggregate    sig  = del.getSign();

    if (DEBUG1) { std::cout << KLBLU << getTag() << " <<<< handling deliver (" << pid << ", " << seq << ", " << val << ") >>>" << KNRM << std::endl; }

    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    if (it1 != this->Rdeliver.end()) {

        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            if (DEBUG) { std::cout << KBLU << "found a corresponding deliver entry" << KNRM << std::endl; }
            //printRdeliver();

            bool tout       = Rdeliver2tout(it2->second);
            PIDS full       = Rdeliver2full(it2->second);
            PIDS tosend     = Rdeliver2tosend(it2->second);
            Aggregate aggr1 = Rdeliver2aggr(it2->second);

            if (opt_switch_full) {
                if (sig.numSigners() >= quorumSize) {
                    if (DEBUG2) { std::cout << KBLU << getTag() << "full(D3):" << sender << KNRM << std::endl; }
                    full.insert(sender);
                } else {
                    if (DEBUG2) { std::cout << KBLU << getTag() << "not full(D3):" << sig.numSigners() << KNRM << std::endl; }
                }
            }

            if (DEBUG) { std::cout << KBLU << aggr1.numSigners() << " + " << sig.numSigners() << KNRM << std::endl; }
            //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 11" << KNRM << std::endl; } }
            aggr1.aggregateWith(aggBound,KF,sig,stats[selfid]);
            if (DEBUG) { std::cout << KBLU << " = " << aggr1.numSigners() << KNRM << std::endl; }


            // Update the echo certificate
            m[val]=mkRdeliverEntry(tout,full,tosend,aggr1);
            it1->second=m;
            //printRdeliver();

        } else {

            // didn't find a corresponding deliver entry
            if (DEBUG) { std::cout << KBLU << getTag() << " deliver entry not found!" << KNRM << std::endl; }

            // NOTE: We handle the corresponding echo to add the echo signatures to our state in case
            // we haven't received enough echo signatures before receiving this deliver.
            // We have to do that because the ones that have delivered stop sending echos and might
            // not reach us through echo messages.
            //
            Message echo(HDR_ECHO,pid,seq,val,{},esig,MODE_ECHO);
            handleEcho(sender, echo);
            deliverMessage(sender,pid,seq,val,esig,sig);

        }

    } else {

        // didn't find a corresponding deliver entry
        if (DEBUG) { std::cout << KBLU << getTag() << " deliver entry not found!" << KNRM << std::endl; }

        // NOTE: We handle the corresponding echo to add the echo signatures to our state in case
        // we haven't received enough echo signatures before receiving this deliver.
        // We have to do that because the ones that have delivered stop sending echos and might
        // not reach us through echo messages.
        //
        Message echo(HDR_ECHO,pid,seq,val,{},esig,MODE_ECHO);
        handleEcho(sender, echo);
        deliverMessage(sender,pid,seq,val,esig,sig);

    }
}


void Process::handleTransfer(PID sender, Message msg) {
    // TODO
}

// It's time to try to become active again
void Process::handleRecover(PID sender, Message msg) {
    status = STATUS_RECOVERING;
    if (DEBUG0) { std::cout << KLBLU << getTag() << " RECOVERING" << KNRM << std::endl; }

    // Scheduling a message to become active again
    Message act(HDR_ACTIVE);
    BroadcastMsg* bmsg = act.to_broadcast();
    activeMsg = bmsg;
    SimTime st = simTime();
    st = st + (((double) (3 * timeout)) / st.getScale());
    if (DEBUG11) { std::cout << KBLU << "scheduling to become active at time " << st << " (scale:" << st.getScale() << ")" << KNRM << std::endl; }
    scheduleAt(st,bmsg);
}


// It's time to become active again
void Process::handleActive(PID sender, Message msg) {
    // since we got the HDR_ACTIVE message, it means that it wasn't canceled
    // and therefore that the process didn't try to re-enter the passive mode.
    // So, it can become active again

    // TODO: we should check that there was some activity at least during the recovery period
    // if not re-start the recovery process

    if (someActivity) {
        status = STATUS_ACTIVE;
        countPassives--;
        if (DEBUG0) { std::cout << KBCYN << getTag() << " ACTIVE AGAIN" << KNRM << std::endl; }
    } else {
        status = STATUS_PASSIVE;
        endSimu = true;
        if (DEBUG0) { std::cout << KBMAG << getTag() << " NO ACTIVITY - STOPPING" << KNRM << std::endl; }
    }
}


bool Process::verifyBroadcast(Message bcast) {
    PROCESS_ID   pid  = bcast.getPid();
    SEQUENCE_NUM seq  = bcast.getSeq();
    VALUE        val  = bcast.getVal();
    Aggregate    aggr = bcast.getSign();

    if (DEBUG) { std::cout << KLBLU << getTag() << " <<< verify broadcast (" << pid << ", " << seq << ", " << val << ") >>>" << KNRM << std::endl; }

    if (validSequenceNumber(pid,seq)) {
        if (DEBUG) { std::cout << KBLU << getTag() << " sequence number is valid" << KNRM << std::endl; }

        // A broadcast message is valid if its signatures are valid
        Aggregate cae = getSignsInRecho(pid,seq,val);
        //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 12" << KNRM << std::endl; } }
        if (aggr.verifyAggregate(KF,cae,this->nodes,PHASE_ECHO,pid,seq,val,stats[selfid])) {

            if (DEBUG) { std::cout << KBLU << getTag() << " broadcast signatures check out" << KNRM << std::endl; }
            return true;

        } else {

            if (DEBUG) { std::cout << KBLU << getTag() << " skipping broadcast message: broadcast signatures don't check out" << KNRM << std::endl; }
            return false;

        }
    } else {

        if (DEBUG) { std::cout << KBLU << getTag() << " skipping broadcast message: sequence number not valid" << KNRM << std::endl; }
        return false;

    }
}


bool Process::newEcho(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate aggr) {

    // if the optimization is turned off (false) then we trivially return true, i.e., the echo message is considered new
    if (!opt_already_all_received) { return true; }

    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RechoEntry>>::iterator it1 = this->Recho.find(ps);

    if (it1 != this->Recho.end()) {

        // We have entries for the pair pid/seq
        if (DEBUG) { std::cout << KBLU << getTag() << " found a corresponding echo entry" << KNRM << std::endl; }
        //printRecho();

        std::map<VALUE,RechoEntry> m = it1->second;
        std::map<VALUE,RechoEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            if (DEBUG) { std::cout << KBLU << getTag() << "found a corresponding echo sub-entry" << KNRM << std::endl; }

            bool lie        = Recho2lie(it2->second);
            bool echoing    = Recho2still(it2->second);
            PIDS full       = Recho2full(it2->second);
            Aggregate signs = Recho2aggr(it2->second);

            if (signs.contains(aggr)) { return false; }
            else { return true; }

        } else {

            // no corresponding entry
            return true;

        }

    } else {

        // no corresponding entry
        return true;

    }
}


bool Process::verifyEcho(Message echo) {
    PROCESS_ID   pid  = echo.getPid();
    SEQUENCE_NUM seq  = echo.getSeq();
    VALUE        val  = echo.getVal();
    Aggregate    aggr = echo.getSign();

    if (DEBUG) { std::cout << KLBLU << getTag() << " <<< verify echo (" << pid << ", " << seq << ", " << val << ") >>>" << KNRM << std::endl; }

    if (validSequenceNumber(pid,seq)) {
        if (DEBUG) { std::cout << KBLU << getTag() << " sequence number is valid" << KNRM << std::endl; }

        if (newEcho(pid,seq,val,aggr)) {

            // An echo message is valid if its signatures are valid
            Aggregate cae = getSignsInRecho(pid,seq,val);
            //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 13" << KNRM << std::endl; } }
            if (aggr.verifyAggregate(KF,cae,this->nodes,PHASE_ECHO,pid,seq,val,stats[selfid])) {

                if (DEBUG6) { std::cout << KBBLU << getTag() << " echo signatures check out" << KNRM << std::endl; }
                return true;

            } else {

                if (DEBUG6) { std::cout << KBLU << getTag() << " skipping echo message: echo signatures don't check out" << KNRM << std::endl; }
                return false;

            }
        } else {

            if (DEBUG6) { std::cout << KBLU << getTag() << " skipping echo message: we already know about all the signatures" << KNRM << std::endl; }
            return false;

        }
    } else {

        if (DEBUG) { std::cout << KBLU << getTag() << " skipping echo message: sequence number not valid" << KNRM << std::endl; }
        return false;

    }
}


bool Process::newDeliver(PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Aggregate esig, Aggregate sig) {

    // if the optimization is turned off (false) then we trivially return true, i.e., the deliver message is considered new
    if (!opt_already_all_received) { return true; }

    ProcSeq ps(pid,seq);
    std::map<ProcSeq,std::map<VALUE,RdeliverEntry>>::iterator it1 = this->Rdeliver.find(ps);

    if (it1 != this->Rdeliver.end()) {

        std::map<VALUE,RdeliverEntry> m = it1->second;
        std::map<VALUE,RdeliverEntry>::iterator it2 = m.find(val);

        if (it2 != m.end()) {

            if (DEBUG) { std::cout << KBLU << getTag() << " found a corresponding deliver entry" << KNRM << std::endl; }
            //printRdeliver();

            bool tout       = Rdeliver2tout(it2->second);
            PIDS full       = Rdeliver2full(it2->second);
            Aggregate aggr1 = Rdeliver2aggr(it2->second);

            if (aggr1.contains(sig)) { return false; }
            else { return true; }

        } else {

            // no corresponding deliver entry
            return true;

        }

    } else {

        // no corresponding deliver entry
        return true;

    }
}


bool Process::verifyDeliver(Message del) {
    PROCESS_ID   pid   = del.getPid();
    SEQUENCE_NUM seq   = del.getSeq();
    VALUE        val   = del.getVal();
    Aggregate    eaggr = del.getEsign();
    Aggregate    aggr  = del.getSign();

    if (DEBUG) { std::cout << KLBLU << getTag() << " <<< verify deliver (" << pid << ", " << seq << ", " << val << ") >>>" << KNRM << std::endl; }

    // A deliver message is valid if its signatures are valid, i.e., the signatures corresponding to the echo part,
    // and the signatures corresponding to the deliver part.
    // Also, the deliver message should contain more than 2*f echo signatures
    if (validSequenceNumber(pid,seq)) {
        if (DEBUG) { std::cout << KBLU << getTag() << " sequence number is valid" << KNRM << std::endl; }

        if (newDeliver(pid,seq,val,eaggr,aggr)) {

            if (eaggr.numSigners() >= quorumSize) {
                Aggregate cae = getSignsInRecho(pid,seq,val);
                //if (DEBUG12) { if (isByz) { std::cout << KRED << getTag() << "byz stats 14" << KNRM << std::endl; } }
                if (eaggr.verifyAggregate(KF,cae,this->nodes,PHASE_ECHO,pid,seq,val,stats[selfid])) {

                    if (DEBUG6) { std::cout << KBBLU << getTag() << " deliver signatures check out (echo part)" << KNRM << std::endl; }
                    Aggregate cad = getSignsInRdeliver(pid,seq,val);
                    if (aggr.verifyAggregate(KF,cad,this->nodes,PHASE_DELIVER,pid,seq,val,stats[selfid])) { //,eaggr)) {

                        if (DEBUG6) { std::cout << KBBLU << getTag() << " deliver signatures check out (deliver part)" << KNRM << std::endl; }
                        return true;

                    } else {

                        if (DEBUG6) { std::cout << KBLU << getTag() << " skipping deliver message: deliver signatures don't check out (deliver part)" << KNRM << std::endl; }
                        return false;

                    }

                } else {

                    if (DEBUG6) { std::cout << KBLU << getTag() << " skipping deliver message: deliver signatures don't check out (echo part)" << KNRM << std::endl; }
                    return false;

                }
            } else {

                if (DEBUG6) { std::cout << KBLU << getTag() << " skipping deliver message: doesn't have enough echo signatures" << KNRM << std::endl; }
                return false;

            }
        } else {

            if (DEBUG6) { std::cout << KBLU << getTag() << " skipping deliver message: we already know about all the deliver signatures" << KNRM << std::endl; }
            return false;

        }
    } else {

        if (DEBUG) { std::cout << KBLU << getTag() << " skipping deliver message: sequence number not valid" << KNRM << std::endl; }
        return false;

    }
}

bool Process::verifyTransfer(Message msg) {
    // TODO
    return false;
}

bool Process::verifyMessage(Message msg) {
    switch (msg.getHeader()) {

    case HDR_BROADCAST: return verifyBroadcast(msg);
    case HDR_ECHO:      return verifyEcho(msg);
    case HDR_DELIVER:   return verifyDeliver(msg);
    case HDR_TRANSFER:  return verifyTransfer(msg);

    // we don't verify internal messages:
    case HDR_START:   return true;
    case HDR_DIFFUSE: return true;
    case HDR_TIMEOUT: return true;
    case HDR_RECOVER: return true;
    case HDR_ACTIVE:  return true;

    }
}

void Process::handleMessage(PID sender, Message msg) {
    //if (DEBUG12) { if (isByz) { std::cout << "ALERT" << std::endl; } }
    if (verifyMessage(msg)) {
        switch (msg.getHeader()) {

        case HDR_BROADCAST:
            handleBroadcast(sender,msg);
            break;

        case HDR_ECHO:
            handleEcho(sender,msg);
            break;

        case HDR_DELIVER:
            handleDeliver(sender,msg);
            break;

        case HDR_TRANSFER:
            handleTransfer(sender,msg);
            break;

        case HDR_START:
            handleStart(sender,msg);
            break;

        case HDR_TIMEOUT:
            handleTimeout(sender,msg);
            break;

        case HDR_RECOVER    :
            handleRecover(sender,msg);
            break;

        case HDR_ACTIVE:
            handleActive(sender,msg);
            break;

        case HDR_DIFFUSE:
            handleDiffuse(sender,msg);
            break;
        }
    }
}


int Process::gateToProcess(int i) {
    if (i < this->selfid) { return i; }
    else { return i+1; }
}


void Process::handleMessage(cMessage *msg) {
    //if (DEBUG0) { std::cout << KLBLU << getTag() << "handling message (id=" << msg->getId() << ")" << KNRM << std::endl; }

    //if (isByz) {
    //    std::cout << selfid << ":" << stats->to_string() << endl;
    //}

    // When this switch is on, we stop the systems as soon as a quorum delivered
    if (switch_stop_as_soon_as_quorum_deliverd) {
      if (quorumSize <= countDelivers) {
        if (DEBUG13) { std::cout << KBMAG << getTag() << "stopping early" << KNRM << std::endl; }
        //callFinish();
        //endSimulation();
        endSimu=true;
      }
    }

    try {
        // we only handle a message if we're not Byzantine
        BroadcastMsg *bm = check_and_cast<BroadcastMsg *>(msg);
        if (!isByz && !endSimu) {
            Message m(bm);
            this->counter++;
            SimTime st = simTime();

            int sender = this->selfid;
            cModule *mod = msg->getSenderModule();
            if (mod) { sender = mod->getIndex(); }

            if (DEBUG11) { if (selfid == 0) {  std::cout << KLBLU << getTag() << "received message (id=" << msg->getId() << ",hdr=" << header2string(m.getHeader())  << ",pid=" << m.getPid() << ",seq=" << m.getSeq() << ",val=" << m.getVal().to_string() << ") from " << sender << KNRM << std::endl; } }

            if (DEBUG) { std::cout << KLBLU << getTag() << " ============ [scale:" << st.getScale() << ";from=" << sender << ";kind=" << header2string(m.getHeader()) << "]" << KNRM << std::endl; }
            if (switch_loss_send || sender == this->selfid || rand() % 100 < (100-probaLosses)) { handleMessage(sender,m); }
            if (DEBUG) { std::cout << KLBLU << getTag() << " ====== [scale:" << st.getScale() << ";from=" << sender << ";kind=" << header2string(m.getHeader()) << "]" << KNRM << std::endl; }
        } else {
            //std::cout << selfid << ":" << isByz << ":" << endSimu << ":" << stats->to_string() << endl;
        }
        //if (DEBUG0 && endSimu) { std::cout << KLBLU << getTag() << "deleting message (id=" << msg->getId() << ")" << KNRM << std::endl; }
        delete msg;
    } catch (cException e) {
        // TODO: We must be active if we reach this...
        if (!isByz && !endSimu) {
            int id;
            int channelId; // TODO: = atoi(msg->getName())?
            std::istringstream iss (msg->getName());
            iss >> channelId;
            if (DEBUG) { std::cout << "msg name: " << msg->getName() << " " << msg->str() << std::endl; }
            if (DEBUG) { std::cout << "selfid=" << this->selfid << ";ChannelId=" << channelId << std::endl; }

            if (outQueues[channelId].isEmpty()) {
//                if (DEBUG) { std::cout << "queue is empty channelId = " << channelId << "; processToGate[channelId] = " << processToGate[channelId] << endl; }
                if (!gate("gate$o", channelId)->getTransmissionChannel()->isBusy()) {
                    if (DEBUG) { std::cout << "queue is empty 1st channelId = " << channelId << endl; }
                    outBdwVector.record(gate("gate$o", channelId)->getTransmissionChannel()->getNominalDatarate());
                    outBdwVector.record(0.0);
                    if (DEBUG) { std::cout << "end if = " << channelId << endl; }
                } else {
                    if (DEBUG) { std::cout << "queue is empty 2nd channelId = " << channelId << endl; }
                    outBdwVector.record(gate("gate$o", channelId)->getTransmissionChannel()->getNominalDatarate());
                }
                if (DEBUG) { std::cout << "end fist if " << endl; }
            } else { // there are messages to send

                if (DEBUG) { std::cout << "queue is not empty channelId = " << channelId << endl; }
                if (!gate("gate$o", channelId)->getTransmissionChannel()->isBusy()) { // channel is not busy
                    outBdwVector.record(gate("gate$o",channelId)->getTransmissionChannel()->getNominalDatarate());
                    outBdwVector.record(0.0);
                    outBdwVector.record(gate("gate$o",channelId)->getTransmissionChannel()->getNominalDatarate());
                    BroadcastMsg *bm = check_and_cast<BroadcastMsg *>(outQueues[channelId].pop());

                    if (rtByzCastMode) {
                        BroadcastMsg *bm = check_and_cast<BroadcastMsg *>(outQueues[channelId].front());
                        // We now check whether we are in the current round to send the message
                        SimTime curTime  = simTime();
                        int scale        = curTime.getScale();
                        //std::cout << "scale:" << scale << std::endl;
                        int lastRound    = (int)(floor(((curTime*scale)/D).dbl()));
                        int msgRound     = bm->getRound();
                        if (msgRound <= lastRound) {
                            bm = check_and_cast<BroadcastMsg *>(outQueues[channelId].pop());
                            send(bm, "gate$o", channelId);
                        }
                        //else {
                        //    outQueues[channelId].insert(bm);
                        //}
                    } else {
                        BroadcastMsg *bm = check_and_cast<BroadcastMsg *>(outQueues[channelId].pop());
                        send(bm, "gate$o", channelId);
                    }

                    if (!channelTimers[channelId]->isScheduled()) {
                        scheduleAt(gate("gate$o", channelId)->getTransmissionChannel()->getTransmissionFinishTime(),
                                   channelTimers[channelId]);
                    }
                } else { // channel is busy
                    outBdwVector.record(gate("gate$o", channelId)->getTransmissionChannel()->getNominalDatarate());
                }
            }
        } else {
            //if (DEBUG0) { std::cout << KLBLU << getTag() << "deleting message (id=" << msg->getId() << ")" << KNRM << std::endl; }
            //delete msg;
        }
    };
}
