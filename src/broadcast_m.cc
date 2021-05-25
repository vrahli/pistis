//
// Generated file, do not edit! Created by nedtool 5.4 from src/broadcast.msg.
//

// Disable warnings about unused variables, empty switch stmts, etc:
#ifdef _MSC_VER
#  pragma warning(disable:4101)
#  pragma warning(disable:4065)
#endif

#if defined(__clang__)
#  pragma clang diagnostic ignored "-Wshadow"
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wunused-parameter"
#  pragma clang diagnostic ignored "-Wc++98-compat"
#  pragma clang diagnostic ignored "-Wunreachable-code-break"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wshadow"
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wunused-parameter"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#  pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#  pragma GCC diagnostic ignored "-Wfloat-conversion"
#endif

#include <iostream>
#include <sstream>
#include "broadcast_m.h"

namespace omnetpp {

// Template pack/unpack rules. They are declared *after* a1l type-specific pack functions for multiple reasons.
// They are in the omnetpp namespace, to allow them to be found by argument-dependent lookup via the cCommBuffer argument

// Packing/unpacking an std::vector
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::vector<T,A>& v)
{
    int n = v.size();
    doParsimPacking(buffer, n);
    for (int i = 0; i < n; i++)
        doParsimPacking(buffer, v[i]);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::vector<T,A>& v)
{
    int n;
    doParsimUnpacking(buffer, n);
    v.resize(n);
    for (int i = 0; i < n; i++)
        doParsimUnpacking(buffer, v[i]);
}

// Packing/unpacking an std::list
template<typename T, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::list<T,A>& l)
{
    doParsimPacking(buffer, (int)l.size());
    for (typename std::list<T,A>::const_iterator it = l.begin(); it != l.end(); ++it)
        doParsimPacking(buffer, (T&)*it);
}

template<typename T, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::list<T,A>& l)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i=0; i<n; i++) {
        l.push_back(T());
        doParsimUnpacking(buffer, l.back());
    }
}

// Packing/unpacking an std::set
template<typename T, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::set<T,Tr,A>& s)
{
    doParsimPacking(buffer, (int)s.size());
    for (typename std::set<T,Tr,A>::const_iterator it = s.begin(); it != s.end(); ++it)
        doParsimPacking(buffer, *it);
}

template<typename T, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::set<T,Tr,A>& s)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i=0; i<n; i++) {
        T x;
        doParsimUnpacking(buffer, x);
        s.insert(x);
    }
}

// Packing/unpacking an std::map
template<typename K, typename V, typename Tr, typename A>
void doParsimPacking(omnetpp::cCommBuffer *buffer, const std::map<K,V,Tr,A>& m)
{
    doParsimPacking(buffer, (int)m.size());
    for (typename std::map<K,V,Tr,A>::const_iterator it = m.begin(); it != m.end(); ++it) {
        doParsimPacking(buffer, it->first);
        doParsimPacking(buffer, it->second);
    }
}

template<typename K, typename V, typename Tr, typename A>
void doParsimUnpacking(omnetpp::cCommBuffer *buffer, std::map<K,V,Tr,A>& m)
{
    int n;
    doParsimUnpacking(buffer, n);
    for (int i=0; i<n; i++) {
        K k; V v;
        doParsimUnpacking(buffer, k);
        doParsimUnpacking(buffer, v);
        m[k] = v;
    }
}

// Default pack/unpack function for arrays
template<typename T>
void doParsimArrayPacking(omnetpp::cCommBuffer *b, const T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimPacking(b, t[i]);
}

template<typename T>
void doParsimArrayUnpacking(omnetpp::cCommBuffer *b, T *t, int n)
{
    for (int i = 0; i < n; i++)
        doParsimUnpacking(b, t[i]);
}

// Default rule to prevent compiler from choosing base class' doParsimPacking() function
template<typename T>
void doParsimPacking(omnetpp::cCommBuffer *, const T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimPacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

template<typename T>
void doParsimUnpacking(omnetpp::cCommBuffer *, T& t)
{
    throw omnetpp::cRuntimeError("Parsim error: No doParsimUnpacking() function for type %s", omnetpp::opp_typename(typeid(t)));
}

}  // namespace omnetpp


// forward
template<typename T, typename A>
std::ostream& operator<<(std::ostream& out, const std::vector<T,A>& vec);

// Template rule which fires if a struct or class doesn't have operator<<
template<typename T>
inline std::ostream& operator<<(std::ostream& out,const T&) {return out;}

// operator<< for std::vector<T>
template<typename T, typename A>
inline std::ostream& operator<<(std::ostream& out, const std::vector<T,A>& vec)
{
    out.put('{');
    for(typename std::vector<T,A>::const_iterator it = vec.begin(); it != vec.end(); ++it)
    {
        if (it != vec.begin()) {
            out.put(','); out.put(' ');
        }
        out << *it;
    }
    out.put('}');
    
    char buf[32];
    sprintf(buf, " (size=%u)", (unsigned int)vec.size());
    out.write(buf, strlen(buf));
    return out;
}

Register_Class(BroadcastMsg)

BroadcastMsg::BroadcastMsg(const char *name, short kind) : ::omnetpp::cPacket(name,kind)
{
    this->hdr = 0;
    this->mode = 0;
    this->inst = 0;
    this->round = 0;
}

BroadcastMsg::BroadcastMsg(const BroadcastMsg& other) : ::omnetpp::cPacket(other)
{
    copy(other);
}

BroadcastMsg::~BroadcastMsg()
{
}

BroadcastMsg& BroadcastMsg::operator=(const BroadcastMsg& other)
{
    if (this==&other) return *this;
    ::omnetpp::cPacket::operator=(other);
    copy(other);
    return *this;
}

void BroadcastMsg::copy(const BroadcastMsg& other)
{
    this->hdr = other.hdr;
    this->pid = other.pid;
    this->seq = other.seq;
    this->val = other.val;
    this->esign = other.esign;
    this->sign = other.sign;
    this->mode = other.mode;
    this->inst = other.inst;
    this->round = other.round;
}

void BroadcastMsg::parsimPack(omnetpp::cCommBuffer *b) const
{
    ::omnetpp::cPacket::parsimPack(b);
    doParsimPacking(b,this->hdr);
    doParsimPacking(b,this->pid);
    doParsimPacking(b,this->seq);
    doParsimPacking(b,this->val);
    doParsimPacking(b,this->esign);
    doParsimPacking(b,this->sign);
    doParsimPacking(b,this->mode);
    doParsimPacking(b,this->inst);
    doParsimPacking(b,this->round);
}

void BroadcastMsg::parsimUnpack(omnetpp::cCommBuffer *b)
{
    ::omnetpp::cPacket::parsimUnpack(b);
    doParsimUnpacking(b,this->hdr);
    doParsimUnpacking(b,this->pid);
    doParsimUnpacking(b,this->seq);
    doParsimUnpacking(b,this->val);
    doParsimUnpacking(b,this->esign);
    doParsimUnpacking(b,this->sign);
    doParsimUnpacking(b,this->mode);
    doParsimUnpacking(b,this->inst);
    doParsimUnpacking(b,this->round);
}

int BroadcastMsg::getHdr() const
{
    return this->hdr;
}

void BroadcastMsg::setHdr(int hdr)
{
    this->hdr = hdr;
}

PROCESS_ID& BroadcastMsg::getPid()
{
    return this->pid;
}

void BroadcastMsg::setPid(const PROCESS_ID& pid)
{
    this->pid = pid;
}

SEQUENCE_NUM& BroadcastMsg::getSeq()
{
    return this->seq;
}

void BroadcastMsg::setSeq(const SEQUENCE_NUM& seq)
{
    this->seq = seq;
}

VALUE& BroadcastMsg::getVal()
{
    return this->val;
}

void BroadcastMsg::setVal(const VALUE& val)
{
    this->val = val;
}

Aggregate& BroadcastMsg::getEsign()
{
    return this->esign;
}

void BroadcastMsg::setEsign(const Aggregate& esign)
{
    this->esign = esign;
}

Aggregate& BroadcastMsg::getSign()
{
    return this->sign;
}

void BroadcastMsg::setSign(const Aggregate& sign)
{
    this->sign = sign;
}

int BroadcastMsg::getMode() const
{
    return this->mode;
}

void BroadcastMsg::setMode(int mode)
{
    this->mode = mode;
}

int BroadcastMsg::getInst() const
{
    return this->inst;
}

void BroadcastMsg::setInst(int inst)
{
    this->inst = inst;
}

int BroadcastMsg::getRound() const
{
    return this->round;
}

void BroadcastMsg::setRound(int round)
{
    this->round = round;
}

class BroadcastMsgDescriptor : public omnetpp::cClassDescriptor
{
  private:
    mutable const char **propertynames;
  public:
    BroadcastMsgDescriptor();
    virtual ~BroadcastMsgDescriptor();

    virtual bool doesSupport(omnetpp::cObject *obj) const override;
    virtual const char **getPropertyNames() const override;
    virtual const char *getProperty(const char *propertyname) const override;
    virtual int getFieldCount() const override;
    virtual const char *getFieldName(int field) const override;
    virtual int findField(const char *fieldName) const override;
    virtual unsigned int getFieldTypeFlags(int field) const override;
    virtual const char *getFieldTypeString(int field) const override;
    virtual const char **getFieldPropertyNames(int field) const override;
    virtual const char *getFieldProperty(int field, const char *propertyname) const override;
    virtual int getFieldArraySize(void *object, int field) const override;

    virtual const char *getFieldDynamicTypeString(void *object, int field, int i) const override;
    virtual std::string getFieldValueAsString(void *object, int field, int i) const override;
    virtual bool setFieldValueAsString(void *object, int field, int i, const char *value) const override;

    virtual const char *getFieldStructName(int field) const override;
    virtual void *getFieldStructValuePointer(void *object, int field, int i) const override;
};

Register_ClassDescriptor(BroadcastMsgDescriptor)

BroadcastMsgDescriptor::BroadcastMsgDescriptor() : omnetpp::cClassDescriptor("BroadcastMsg", "omnetpp::cPacket")
{
    propertynames = nullptr;
}

BroadcastMsgDescriptor::~BroadcastMsgDescriptor()
{
    delete[] propertynames;
}

bool BroadcastMsgDescriptor::doesSupport(omnetpp::cObject *obj) const
{
    return dynamic_cast<BroadcastMsg *>(obj)!=nullptr;
}

const char **BroadcastMsgDescriptor::getPropertyNames() const
{
    if (!propertynames) {
        static const char *names[] = {  nullptr };
        omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
        const char **basenames = basedesc ? basedesc->getPropertyNames() : nullptr;
        propertynames = mergeLists(basenames, names);
    }
    return propertynames;
}

const char *BroadcastMsgDescriptor::getProperty(const char *propertyname) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    return basedesc ? basedesc->getProperty(propertyname) : nullptr;
}

int BroadcastMsgDescriptor::getFieldCount() const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    return basedesc ? 9+basedesc->getFieldCount() : 9;
}

unsigned int BroadcastMsgDescriptor::getFieldTypeFlags(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeFlags(field);
        field -= basedesc->getFieldCount();
    }
    static unsigned int fieldTypeFlags[] = {
        FD_ISEDITABLE,
        FD_ISCOMPOUND,
        FD_ISCOMPOUND,
        FD_ISCOMPOUND,
        FD_ISCOMPOUND,
        FD_ISCOMPOUND,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
        FD_ISEDITABLE,
    };
    return (field>=0 && field<9) ? fieldTypeFlags[field] : 0;
}

const char *BroadcastMsgDescriptor::getFieldName(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldName(field);
        field -= basedesc->getFieldCount();
    }
    static const char *fieldNames[] = {
        "hdr",
        "pid",
        "seq",
        "val",
        "esign",
        "sign",
        "mode",
        "inst",
        "round",
    };
    return (field>=0 && field<9) ? fieldNames[field] : nullptr;
}

int BroadcastMsgDescriptor::findField(const char *fieldName) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    int base = basedesc ? basedesc->getFieldCount() : 0;
    if (fieldName[0]=='h' && strcmp(fieldName, "hdr")==0) return base+0;
    if (fieldName[0]=='p' && strcmp(fieldName, "pid")==0) return base+1;
    if (fieldName[0]=='s' && strcmp(fieldName, "seq")==0) return base+2;
    if (fieldName[0]=='v' && strcmp(fieldName, "val")==0) return base+3;
    if (fieldName[0]=='e' && strcmp(fieldName, "esign")==0) return base+4;
    if (fieldName[0]=='s' && strcmp(fieldName, "sign")==0) return base+5;
    if (fieldName[0]=='m' && strcmp(fieldName, "mode")==0) return base+6;
    if (fieldName[0]=='i' && strcmp(fieldName, "inst")==0) return base+7;
    if (fieldName[0]=='r' && strcmp(fieldName, "round")==0) return base+8;
    return basedesc ? basedesc->findField(fieldName) : -1;
}

const char *BroadcastMsgDescriptor::getFieldTypeString(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldTypeString(field);
        field -= basedesc->getFieldCount();
    }
    static const char *fieldTypeStrings[] = {
        "int",
        "PROCESS_ID",
        "SEQUENCE_NUM",
        "VALUE",
        "Aggregate",
        "Aggregate",
        "int",
        "int",
        "int",
    };
    return (field>=0 && field<9) ? fieldTypeStrings[field] : nullptr;
}

const char **BroadcastMsgDescriptor::getFieldPropertyNames(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldPropertyNames(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        case 0: {
            static const char *names[] = { "enum",  nullptr };
            return names;
        }
        case 6: {
            static const char *names[] = { "enum",  nullptr };
            return names;
        }
        default: return nullptr;
    }
}

const char *BroadcastMsgDescriptor::getFieldProperty(int field, const char *propertyname) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldProperty(field, propertyname);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        case 0:
            if (!strcmp(propertyname,"enum")) return "HEADER";
            return nullptr;
        case 6:
            if (!strcmp(propertyname,"enum")) return "MODE";
            return nullptr;
        default: return nullptr;
    }
}

int BroadcastMsgDescriptor::getFieldArraySize(void *object, int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldArraySize(object, field);
        field -= basedesc->getFieldCount();
    }
    BroadcastMsg *pp = (BroadcastMsg *)object; (void)pp;
    switch (field) {
        default: return 0;
    }
}

const char *BroadcastMsgDescriptor::getFieldDynamicTypeString(void *object, int field, int i) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldDynamicTypeString(object,field,i);
        field -= basedesc->getFieldCount();
    }
    BroadcastMsg *pp = (BroadcastMsg *)object; (void)pp;
    switch (field) {
        default: return nullptr;
    }
}

std::string BroadcastMsgDescriptor::getFieldValueAsString(void *object, int field, int i) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldValueAsString(object,field,i);
        field -= basedesc->getFieldCount();
    }
    BroadcastMsg *pp = (BroadcastMsg *)object; (void)pp;
    switch (field) {
        case 0: return enum2string(pp->getHdr(), "HEADER");
        case 1: {std::stringstream out; out << pp->getPid(); return out.str();}
        case 2: {std::stringstream out; out << pp->getSeq(); return out.str();}
        case 3: {std::stringstream out; out << pp->getVal(); return out.str();}
        case 4: {std::stringstream out; out << pp->getEsign(); return out.str();}
        case 5: {std::stringstream out; out << pp->getSign(); return out.str();}
        case 6: return enum2string(pp->getMode(), "MODE");
        case 7: return long2string(pp->getInst());
        case 8: return long2string(pp->getRound());
        default: return "";
    }
}

bool BroadcastMsgDescriptor::setFieldValueAsString(void *object, int field, int i, const char *value) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->setFieldValueAsString(object,field,i,value);
        field -= basedesc->getFieldCount();
    }
    BroadcastMsg *pp = (BroadcastMsg *)object; (void)pp;
    switch (field) {
        case 0: pp->setHdr((HEADER)string2enum(value, "HEADER")); return true;
        case 6: pp->setMode((MODE)string2enum(value, "MODE")); return true;
        case 7: pp->setInst(string2long(value)); return true;
        case 8: pp->setRound(string2long(value)); return true;
        default: return false;
    }
}

const char *BroadcastMsgDescriptor::getFieldStructName(int field) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructName(field);
        field -= basedesc->getFieldCount();
    }
    switch (field) {
        case 1: return omnetpp::opp_typename(typeid(PROCESS_ID));
        case 2: return omnetpp::opp_typename(typeid(SEQUENCE_NUM));
        case 3: return omnetpp::opp_typename(typeid(VALUE));
        case 4: return omnetpp::opp_typename(typeid(Aggregate));
        case 5: return omnetpp::opp_typename(typeid(Aggregate));
        default: return nullptr;
    };
}

void *BroadcastMsgDescriptor::getFieldStructValuePointer(void *object, int field, int i) const
{
    omnetpp::cClassDescriptor *basedesc = getBaseClassDescriptor();
    if (basedesc) {
        if (field < basedesc->getFieldCount())
            return basedesc->getFieldStructValuePointer(object, field, i);
        field -= basedesc->getFieldCount();
    }
    BroadcastMsg *pp = (BroadcastMsg *)object; (void)pp;
    switch (field) {
        case 1: return (void *)(&pp->getPid()); break;
        case 2: return (void *)(&pp->getSeq()); break;
        case 3: return (void *)(&pp->getVal()); break;
        case 4: return (void *)(&pp->getEsign()); break;
        case 5: return (void *)(&pp->getSign()); break;
        default: return nullptr;
    }
}


