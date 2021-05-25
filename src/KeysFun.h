#ifndef KEYSFUN_H
#define KEYSFUN_H

#include <string>
#include <openssl/rsa.h>
#include <openssl/ec.h>
//#include <pbc.h>

#include "config.h"
#include "types.h"


#define NO_key  unit*
#define RSA_key RSA*
#define EC_key  EC_KEY*
//#define BLS_key element_t*


#ifdef KK_NO
    typedef NO_key KEY;
#endif
#ifdef KK_RSA4096
  typedef RSA_key KEY;
#endif
#ifdef KK_RSA2048
  typedef RSA_key KEY;
#endif
#ifdef KK_EC521
  typedef EC_key KEY;
#endif
#ifdef KK_EC256
  typedef EC_key KEY;
#endif
#ifdef KK_BLS
  typedef BLS_key KEY;
#endif


/*void newKEY(KEY key);*/

class KeysFun {

    private:
      //pairing_t pairing;
      //element_t bls_g;
    public:
      //std::string getBlsParams();
      //void setBlsG();
      //element_t* getBlsG();
      //void clearBls();
      //void initG2(element_t *e);
      //void initG1(element_t *e);
      //void initGT(element_t *e);
      //void initZr(element_t *e);

      int loadPrivateKey(PROCESS_ID id, NO_key*  priv);
      int loadPrivateKey(PROCESS_ID id, RSA_key* priv);
      int loadPrivateKey(PROCESS_ID id, EC_key*  priv);
      //int loadPrivateKey(PROCESS_ID id, BLS_key* priv);

      int loadPublicKey(PROCESS_ID id, NO_key*  pub);
      int loadPublicKey(PROCESS_ID id, RSA_key* pub);
      int loadPublicKey(PROCESS_ID id, EC_key*  pub);
      //int loadPublicKey(PROCESS_ID id, BLS_key* pub);

      void generateRsa4096Keys(int id);
      void generateRsa2048Keys(int id);
      void generateEc521Keys(int id);
      void generateEc256Keys(int id);
      void generateBlsKeys(int id);

};

#endif
