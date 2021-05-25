#include <algorithm>
#include <iostream>
#include <fstream>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
//#include <pbc.h>
#include <chrono>
#include <cassert>

#include "config.h"
#include "Sign.h"



std::ostream& operator<<(std::ostream& os, const SIGN& s) {
  for (std::array<unsigned char,SIGN_LEN>::const_iterator it=s.sign.begin(); it!=s.sign.end(); ++it) {
    os << *it;
  }
  return os;
}

bool SIGN::operator==(const SIGN& s) const {
#ifdef MULTISIG
    return (signers == s.signers && sign == s.sign);
#else
    return (signer == s.signer && sign == s.sign);
#endif
}

bool SIGN::operator<(const SIGN& s) const {
#ifdef MULTISIG
    return (signers < s.signers);
#else
    return (signer < s.signer);
#endif
    /*
    if (signers.size() < s.signers.size()) { return true; }
    else if (signers.size() == s.signers.size()) {
        std::set<PROCESS_ID>::iterator it1=signers.begin();
        for (std::set<PROCESS_ID>::iterator it2=s.signers.begin(); it1!=signers.end() && it2!=s.signers.end(); ++it1, ++it2) {
            if (*it1 < *it2) { return true; }
            else if (*it1 > *it2) { return false; }
        }
        return false;
    } else { return false; }*/
}


SIGN::SIGN() {}

/*SIGN::SIGN(PROCESS_ID signer, char c) {
  this->signers.insert(signer);
  this->sign.fill(c);
}

SIGN::SIGN(PROCESS_ID signer, std::array<unsigned char,SIGN_LEN> s) {
  this->signers.insert(signer);
  this->sign = s;
}

SIGN::SIGN(PROCESS_ID signer, unsigned char s[SIGN_LEN]) {
  this->signers.insert(signer);
  std::copy(s, s + SIGN_LEN, std::begin(this->sign));
}*/

static void printHex(const char *title, const unsigned char *s, int len) {
  int n;
  printf("%s:", title);
  for (n = 0; n < len; ++n) {
    if ((n % 16) == 0) {
      printf("\n%04x", n);
    }
    printf(" %02x", s[n]);
  }
  printf("\n");
}


void signText(KeysFun KF, PROCESS_ID id, std::string text, NO_key priv, unsigned char sign[SIGN_LEN]) {
    //std::cout << "not signing" << std::endl;
}


/*void evp_signText(KeysFun KF, PROCESS_ID id, std::string text, RSA_key priv, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "signing text using EC" << KNRM << std::endl; }
  unsigned int signLen=0;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  EVP_PKEY * key = EVP_PKEY_new();
  assert(1==EVP_PKEY_assign_RSA_KEY(key, priv));

  EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key,NULL);
  assert(1==EVP_PKEY_sign_init(key_ctx));
  assert(1==EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()));

//  assert(1==EVP_PKEY_sign(key_ctx,NULL,&signLen, hash, SHA256_DIGEST_LENGTH));
  //sign.assign(sigLen,0);
  //EVP_MD_CTX * md_ctx = EVP_MD_CTX_new();
  //EVP_MD_CTX_set_pkey_ctx(md_ctx, key_ctx);
  assert(1==EVP_PKEY_sign(key_ctx, sign, &signLen, hash, SHA256_DIGEST_LENGTH));

  EVP_PKEY_CTX_free(key_ctx);
  EVP_PKEY_free(key);
}*/



void signText(KeysFun KF, PROCESS_ID id, std::string text, RSA_key priv, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "signing text using RSA" << KNRM << std::endl; }
  unsigned int signLen;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  if (!RSA_sign (NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &signLen, priv)) {
    std::cout << KCYN << "RSA_sign failed" << KNRM << std::endl;
    exit(0);
  }

  // printHex("SIGN", sign, signLen);
  //printf("Signature length = %d\n", signLen);

  //std::cout << KCYN << "Result: " << sign << KNRM << std::endl;
}


/*void evp_signText(KeysFun KF, PROCESS_ID id, std::string text, EC_key priv, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "signing text using EC" << KNRM << std::endl; }
  unsigned int signLen=0;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  EVP_PKEY * key = EVP_PKEY_new();
  assert(1==EVP_PKEY_assign_EC_KEY(key, priv));

  EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key,NULL);
  assert(1==EVP_PKEY_sign_init(key_ctx));
  assert(1==EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()));

//  assert(1==EVP_PKEY_sign(key_ctx,NULL,&signLen, hash, SHA256_DIGEST_LENGTH));
  //sign.assign(sigLen,0);
  //EVP_MD_CTX * md_ctx = EVP_MD_CTX_new();
  //EVP_MD_CTX_set_pkey_ctx(md_ctx, key_ctx);
  assert(1==EVP_PKEY_sign(key_ctx, sign, &signLen, hash, SHA256_DIGEST_LENGTH));

  EVP_PKEY_CTX_free(key_ctx);
  EVP_PKEY_free(key);
}*/


void signText(KeysFun KF, PROCESS_ID id, std::string text, EC_key priv, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "signing text using EC" << KNRM << std::endl; }
  unsigned int signLen;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  if (!ECDSA_sign (NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &signLen, priv)) {
    std::cout << KCYN << "ECDSA_sign failed" << KNRM << std::endl;
    exit(0);
  }
  //if (DEBUG) { std::cout << KCYN << "signature size: " << signLen << KNRM << std::endl; }
}


/*void signText(KeysFun KF, PROCESS_ID id, std::string text, BLS_key priv, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "signing text using BLS" << KNRM << std::endl; }
  unsigned int signLen;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  // -- generates an element corresponding to the above hash
  element_t h;
  KF.initG1(&h);
  element_from_hash(h, hash, SHA256_DIGEST_LENGTH); // Store h = hash('hashofmessage'). What is 13 for?

  // -- signs the hash using the private key
  element_t sgn;
  KF.initG1(&sgn);
  element_pow_zn(sgn, h, *priv); // signs[0] = h^secret_keys[0]

  // -- exports the signatures to a list of bytes
  int n = element_to_bytes(sign, sgn);
  if (DEBUG) { std::cout << KCYN << "exporting BLS signature of size " << n << KNRM << std::endl; }

  element_clear(h);
  element_clear(sgn);
}*/


bool verifyText(KeysFun KF, std::string text, NO_key pub, unsigned char sign[SIGN_LEN]) { return true; }


/*bool evp_verifyText(KeysFun KF, std::string text, RSA_key pub, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "verifying text using RSA" << KNRM << std::endl; }
  unsigned int signLen = SIGN_LEN;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  EVP_PKEY * key = EVP_PKEY_new();
  assert(1==EVP_PKEY_assign_RSA_KEY(key, pub));

  EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key,NULL);

  assert(1==EVP_PKEY_verify_init(key_ctx));
  assert(1==EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()));

  //EVP_MD_CTX * md_ctx = EVP_MD_CTX_new();
  //EVP_MD_CTX_set_pkey_ctx(md_ctx, key_ctx);
  const int b=EVP_PKEY_verify(key_ctx, sign, signLen, hash, SHA256_DIGEST_LENGTH);

  EVP_PKEY_CTX_free(key_ctx);
  EVP_PKEY_free(key);

  return b;
}*/


bool verifyText(KeysFun KF, std::string text, RSA_key pub, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "verifying text using RSA" << KNRM << std::endl; }
  unsigned int signLen = SIGN_LEN;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  bool b = RSA_verify (NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, signLen, pub);

  // printHex("VERIFY", sign, signLen);
  // printf("Signature length = %d\n", signLen);

  return b;
}


/*bool evp_verifyText(KeysFun KF, std::string text, EC_key pub, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "verifying text using EC" << KNRM << std::endl; }
  unsigned int signLen = SIGN_LEN;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

//  bool b = ECDSA_verify (NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, signLen, pub);

  EVP_PKEY * key = EVP_PKEY_new();
  assert(1==EVP_PKEY_assign_EC_KEY(key, pub));

  EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key,NULL);

  assert(1==EVP_PKEY_verify_init(key_ctx));
  assert(1==EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()));

  //EVP_MD_CTX * md_ctx = EVP_MD_CTX_new();
  //EVP_MD_CTX_set_pkey_ctx(md_ctx, key_ctx);
  const int b=EVP_PKEY_verify(key_ctx, sign, signLen, hash, SHA256_DIGEST_LENGTH);

  EVP_PKEY_CTX_free(key_ctx);
  EVP_PKEY_free(key);

  return b;
}*/


bool verifyText(KeysFun KF, std::string text, EC_key pub, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "verifying text using EC" << KNRM << std::endl; }
  unsigned int signLen = SIGN_LEN;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  //auto t1 = std::chrono::high_resolution_clock::now();

  bool b = ECDSA_verify (NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, signLen, pub);

  // auto t2 = std::chrono::high_resolution_clock::now();

  // unsigned char hash2[SHA256_DIGEST_LENGTH];

  // if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash2)){
  //   std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
  //   exit(0);
  // }

  // auto t3 = std::chrono::high_resolution_clock::now();

  // bool b2 = ECDSA_verify (NID_sha256, hash2, SHA256_DIGEST_LENGTH, sign, signLen, pub);

  // auto t4 = std::chrono::high_resolution_clock::now();

  // double time1 = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
  // double time2 = std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
  // std::cout << KGRN << ":ECDSA-verify-time1=" << time1 << ":time2=" << time2 << ":hash=" << hash << ":sign-len=" << signLen << KNRM << std::endl;

  return b;
}


void SIGN::test(KeysFun KF, PROCESS_ID id, std::string text, KEY priv, KEY pub, unsigned char sign[SIGN_LEN]) {
  auto start = std::chrono::steady_clock::now();
  auto end = std::chrono::steady_clock::now();
  unsigned int repetition = 1000;
  double time = 0.0;

  double count = 0.0;

  for (int i = 0; i < repetition; i++) {
    start = std::chrono::steady_clock::now();
    signText(KF, id, text, priv, sign);
    end = std::chrono::steady_clock::now();
    time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    count += time;
  }
  std::cout << "EC-sig-time:" << count / repetition << std::endl;

  count = 0.0;

  for (int i = 0; i < repetition; i++) {
    start = std::chrono::steady_clock::now();
    signText(KF, id, text, priv, sign);
    end = std::chrono::steady_clock::now();
    time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    count += time;
  }
  std::cout << "evp-EC-sig-time:" << count / repetition << std::endl;

  count = 0.0;

  for (int i = 0; i < repetition; i++) {
    signText(KF, id, text, priv, sign);
    start = std::chrono::steady_clock::now();
    verifyText(KF, text, pub, sign);
    end = std::chrono::steady_clock::now();
    time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    count += time;
  }
  std::cout << "EC-verif-time:" << count / repetition << std::endl;

  count = 0.0;

  for (int i = 0; i < repetition; i++) {
    signText(KF, id, text, priv, sign);
    start = std::chrono::steady_clock::now();
    verifyText(KF, text, pub, sign);
    end = std::chrono::steady_clock::now();
    time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    count += time;
  }
  std::cout << "EC-verif-time:" << count / repetition << std::endl;
}



/*bool verifyText(KeysFun KF, std::string text, BLS_key pub, unsigned char sign[SIGN_LEN]) {
  if (DEBUG) { std::cout << KCYN << "verifying text using BLS" << KNRM << std::endl; }
  unsigned int signLen = SIGN_LEN;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  if (!SHA256 ((const unsigned char *)text.c_str(), text.size(), hash)){
    std::cout << KCYN << "SHA1 failed" << KNRM << std::endl;
    exit(0);
  }

  // -- generates an element corresponding to the signature sign
  element_t sgn;
  KF.initG1(&sgn);
  int n = element_from_bytes(sgn, sign);
  if (DEBUG) { std::cout << KCYN << "loading BLS signature of size " << n << KNRM << std::endl; }

  // -- generates an element corresponding to the above hash
  element_t h;
  KF.initG1(&h);
  element_from_hash(h, hash, SHA256_DIGEST_LENGTH); // Store h = hash('hashofmessage'). What is 13 for?

  // -- now we start verifying
  element_t x1, x2;
  KF.initGT(&x1);
  KF.initGT(&x2);

  // for a multisignature (in aggregate), we would have to multiply 'sgn' with the rest of the signatures using element_mul
  element_pairing(x1, sgn, *KF.getBlsG());
  element_pairing(x2, h, *pub);

  bool b = !element_cmp(x1, x2);

  element_clear(h);
  element_clear(sgn);
  element_clear(x1);
  element_clear(x2);

  return b;
}*/


std::string SIGN::toString() {
  std::string s;
  for (std::array<unsigned char,SIGN_LEN>::const_iterator it=this->sign.begin(); it!=this->sign.end(); ++it) {
    s += *it;
  }
  return s;
}

std::string signs2string(std::set<SIGN> signs) {
  std::string s;
  for (std::set<SIGN>::iterator it = signs.begin(); it != signs.end(); ++it) {
    s += ((SIGN)(*it)).toString();
  }
  return s;
}

std::string str_of_phase(PHASE phase) {
    switch (phase) {
    case PHASE_ECHO:    return "0";
    case PHASE_DELIVER: return "1";
    }
}


SIGN::SIGN(KeysFun KF, KEY priv, PROCESS_ID signer, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val) {
#ifdef MULTISIG
  this->signers.insert(signer);
#else
  this->signer = signer;
#endif
  //if (DEBUG4) { std::cout << KCYN << signer << ":signing@" << phase << KNRM << std::endl; }
  //std::cout << KCYN << "making signature " << this->sign << KNRM << std::endl;
  //this->sign = {};
  unsigned char s[SIGN_LEN];
  std::string text = str_of_phase(phase) + std::to_string(pid) + std::to_string(seq) + val.to_string();
  //std::cout << KCYN << "making signature " << this->sign << KNRM << std::endl;

  //auto start = std::chrono::high_resolution_clock::now();
  signText(KF,signer,text,priv,s);
  //auto end = std::chrono::high_resolution_clock::now();
  //std::cout << KCYN << signer << ":" << phase << ":" << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << std::endl;

  //std::cout << KCYN << "signature " << s << KNRM << std::endl;
  //std::cout << KCYN << "signature " << this->sign << KNRM << std::endl;
  std::copy(s, s + SIGN_LEN, std::begin(this->sign));
  //std::cout << KCYN << "returning signature " << this->sign << KNRM << std::endl;
}


/*SIGN::SIGN(KEY priv, PROCESS_ID signer, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, std::set<SIGN> signs) {
  this->signers.insert(signer);
  //std::cout << KCYN << "making signature" << KNRM << std::endl;
  unsigned char sign[SIGN_LEN];
  std::string text = std::to_string(pid) + std::to_string(seq) + std::to_string(val) + signs2string(signs);
  signText(signer,text,priv,sign);
  std::copy(sign, sign + SIGN_LEN, std::begin(this->sign));
  //std::cout << KCYN << "returning signature: " << this->sign << KNRM << std::endl;
}*/


std::array<unsigned char,SIGN_LEN> SIGN::getSign() { return this->sign; }


#ifdef MULTISIG
std::multiset<PROCESS_ID> SIGN::getSigners() { return this->signers; }
#else
PROCESS_ID SIGN::getSigner() { return this->signer; }
#endif


bool SIGN::verifySign(KeysFun KF, KEY pub, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats &stats) {
  std::string text = str_of_phase(phase) + std::to_string(pid) + std::to_string(seq) + val.to_string();
  //unsigned char sign[SIGN_LEN];
  //std::copy(std::begin(this->sign), std::end(this->sign), std::begin(sign));
  //unsigned char sign[SIGN_LEN];
  //unsigned char *s = &this->sign[0];
  //for (int i = 0; i < SIGN_LEN; i++) { sign[i]=s[i]; }
  unsigned char *sign = &this->sign[0];
  //auto start = std::chrono::steady_clock::now();
  bool b = verifyText(KF,text,pub,sign);
  //auto end = std::chrono::steady_clock::now();
  //std::cout << "one-V:" << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << std::endl;
  //double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
  //stats.incrementCryptoTimeVerif(time);
  //stats.incrementNumVerif();
  // if (DEBUG13 && time > 1000) {
  //   std::cout << KGRN << ":" << stats.getId() << ":verif-time:" << time << ":text:" << text << KNRM << std::endl;
  //   std::ofstream fsto;
  //   fsto.open("verif-time", std::ofstream::out | std::ofstream::app);
  //   fsto << time << std::endl;
  //   fsto.close();
  // }
  if (DEBUG) { std::cout << KCYN << "verified signature: " << b << KNRM << std::endl; }
  return b;
  //return true;
}


/*bool SIGN::verifySign(KEY pub, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, std::set<SIGN> signs) {
  std::string text = std::to_string(pid) + std::to_string(seq) + std::to_string(val) + signs2string(signs);
  unsigned char *sign = &this->sign[0];
  bool b = verifyText(text,pub,sign);
  if (DEBUG) { std::cout << KCYN << "verified signature: " << b << KNRM << std::endl; }
  return b;
  //return true;
}*/


/* if MULTISIG is set we multiply the public keys of the signers
 * otherwise we simply verify the signature for each signer
 */
bool SIGN::verifySign(KeysFun KF, Nodes nodes, PHASE phase, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, Stats &stats) {
#ifdef MULTISIG
    if (DEBUG) { std::cout << KGRN << "checking " << this->signers.size() << " signers" << KNRM << std::endl; }
    element_t key;
    KF.initG2(&key);
    element_set1(key);
    for (std::multiset<PROCESS_ID>::iterator it=this->signers.begin(); it!=this->signers.end(); ++it) {
        PROCESS_ID signer = (PROCESS_ID)*it;
        if (DEBUG) { std::cout << KGRN << "getting " << signer << "'s key" << KNRM << std::endl; }
        NodeInfo *nfo = nodes.find(signer);
        if (nfo) {
            element_mul(key, key, *(nfo->getPub()));
        }
    }
    bool verif = verifySign(KF,&key,phase,pid,seq,val,stats);
    if (!verif) { return false; }
    element_clear(key);
#else
    if (DEBUG) { std::cout << KGRN << "checking signature from " << this->signer << KNRM << std::endl; }
    NodeInfo * nfo = nodes.find(this->signer);
    if (nfo) {
        if (DEBUG) { std::cout << KGRN << "found info for " << nfo->getPid() << KNRM << std::endl; }
        bool verif = verifySign(KF,nfo->getPub(),phase,pid,seq,val,stats);
        if (!verif) { return false; }
    } else { return false; }
#endif
    //if (DEBUG) { std::cout << KGRN << "checked all signers" << KNRM << std::endl; }
    return true;
}


/*bool SIGN::verifySign(Nodes nodes, PROCESS_ID pid, SEQUENCE_NUM seq, VALUE val, std::set<SIGN> signs) {
    if (DEBUG) { std::cout << KGRN << "checking " << this->signers.size() << " signers" << KNRM << std::endl; }
#ifdef MULTISIG
    element_t key;
    initG2(&key);
    element_set1(key);
    for (std::multiset<PROCESS_ID>::iterator it=this->signers.begin(); it!=this->signers.end(); ++it) {
        PROCESS_ID signer = (PROCESS_ID)*it;
        NodeInfo *nfo = nodes.find(signer);
        if (nfo) {
            element_mul(key, key, *(nfo->getPub()));
        }
    }
    if (!verifySign(&key,pid,seq,val,signs)) { return false; }
    element_clear(key);
#else
    for (std::multiset<PROCESS_ID>::iterator it=this->signers.begin(); it!=this->signers.end(); ++it) {
        PROCESS_ID signer = (PROCESS_ID)*it;
        if (DEBUG) { std::cout << KGRN << "checking signature from " << signer << KNRM << std::endl; }
        NodeInfo *nfo = nodes.find(signer);
        if (nfo) {
            if (DEBUG) { std::cout << KGRN << "found info for " << nfo->getPid() << KNRM << std::endl; }
            if (!verifySign(nfo->getPub(),pid,seq,val,signs)) { return false; }
        } else { return false; }
    }
#endif
    //if (DEBUG) { std::cout << KGRN << "checked all signers" << KNRM << std::endl; }
    return true;
}*/


void SIGN::copy(unsigned char sign[SIGN_LEN]) {
    std::copy(std::begin(this->sign), std::begin(this->sign) + SIGN_LEN, sign);
  /*for (std::array<unsigned char,SIGN_LEN>::const_iterator it=this->sign.begin(); it!=this->sign.end(); ++it) {
    sign += *it;
  }*/
}


void SIGN::printSigners() {
#ifdef MULTISIG
    for (std::multiset<PROCESS_ID>::iterator it = this->signers.begin(); it != this->signers.end(); ++it) {
        if (DEBUG3) { std::cout << KGRN << "--signer:" << *it << KNRM << std::endl; }
    }
#else
    if (DEBUG3) { std::cout << KGRN << "--signer:" << this->signer << KNRM << std::endl; }
#endif
}


int SIGN::numSigners() {
#ifdef MULTISIG
    std::set<PROCESS_ID> l = {};
    std::multiset<PROCESS_ID> k = this->signers;
    for (std::multiset<PROCESS_ID>::iterator it = k.begin(); it != k.end(); ++it) {
        l.insert(*it);
    }
    return l.size();
#else
    return 1;
#endif
}

int SIGN::size() {
    int s1 = SIGN_LEN * sizeof(unsigned char);
    int m = 1;
#ifdef MULTISIG
    m = this->signers.size();
#endif
    int s2 = m * sizeof(PROCESS_ID);
    return s1 + s2;
}


void SIGN::combine(KeysFun KF, SIGN sign) {
#ifdef KK_BLS
    unsigned char s1[SIGN_LEN];
    unsigned char s2[SIGN_LEN];
    element_t sgn1, sgn2;
    KF.initG1(&sgn1);
    KF.initG1(&sgn2);
    this->copy(s1);
    sign.copy(s2);
    int n1 = element_from_bytes(sgn1, s1);
    int n2 = element_from_bytes(sgn2, s2);
    element_mul(sgn1, sgn1, sgn2);
    int n = element_to_bytes(std::begin(this->sign), sgn1);

    std::multiset<PROCESS_ID> k = sign.getSigners();
    if (DEBUG) { std::cout << KGRN << "adding " << k.size() << " signers (to " << this->signers.size() << ")" << KNRM << std::endl; }
    if (DEBUG) { printSigners(); }
    for (std::multiset<PROCESS_ID>::iterator it = k.begin(); it != k.end(); ++it) {
        PROCESS_ID id = *it;
        this->signers.insert(id);
        if (DEBUG) { std::cout << KGRN << "added " << id << KNRM << std::endl; }
    }
    if (DEBUG) { std::cout << KGRN << "added signers (now " << this->signers.size() << ")" << KNRM << std::endl; }

    element_clear(sgn1);
    element_clear(sgn2);
#endif
}
