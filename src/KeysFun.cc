#include <iostream>
#include <fstream>
#include <stdio.h> 
#include <string>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>


#include "config.h"
#include "KeysFun.h"


std::string dir = "somekeys/";
std::string bls_params =
  //   "type a q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791 h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776 r 730750818665451621361119245571504901405976559617 exp2 159 exp1 107 sign1 1 sign0 1";
  "type a1 p 48512875896303752499712277254589628516419352188294521198189567511009073158115045361294839347099315898960045398524682007334164928531594799149100548036445760110913157420655690361891290858441360807158247259460501343449199712532828063940008683740048500980441989713739689655610578458388126934242630557397618776539259 n 36203638728584889925158415861634051131656232976339194924022065306723188923966451762160327870969638730567198058600508960697138006366861790409776528385407283664860565239295291314844246909284597617282274074224254733917313218308080644731349763985110821627195514711746037056425804819692632040479575042834043863089 l 1340";


/*void KeysFun::setBlsG() {
    pairing_init_set_str(pairing, getBlsParams().c_str());

    element_init_G2(bls_g, pairing);

    std::string bytes = "[10932693706606530729889730854866017939000611755037186314671323201555494278337456048913842403917484787134922886632190464938217423681180745511556152025382850286224372198992902271646251102402959635712237409651421382343180208589625416273107652187980207565259744904135778849993051780814813553094336729720192625556281, 2251501069823976557156384651991230144380811647457242088421905616945919492338412199999176224191245431276194280928093761307809849926635342592469282406207326966504038145988512287823569645669424731877513367629979743196343197965487447259082993252965562831721846511794206678954459681173348061907026008586780396661556]";
    int nbytes = element_set_str(bls_g, bytes.c_str(), 10);
    //element_random(g); // generate random g
    //element_printf("system parameter g = %B\n\n", g);
}*/


// element_t* KeysFun::getBlsG() { return &bls_g; }


/*std::string KeysFun::getBlsParams() {
    return bls_params;
}*/


/*void KeysFun::clearBls() {
    element_clear(bls_g);
    pairing_clear(pairing);
}*/


//void KeysFun::initZr(element_t *e) { element_init_Zr(*e, pairing); }
//void KeysFun::initG1(element_t *e) { element_init_G1(*e, pairing); }
//void KeysFun::initG2(element_t *e) { element_init_G2(*e, pairing); }
//void KeysFun::initGT(element_t *e) { element_init_GT(*e, pairing); }


int KeysFun::loadPrivateKey(PROCESS_ID id, NO_key* priv) { return 0; }
int KeysFun::loadPublicKey(PROCESS_ID pid, NO_key* pub) { return 0; }


int KeysFun::loadPrivateKey(PROCESS_ID id, RSA_key* priv) {
    if (DEBUG) std::cout << KYEL << "loading private key" << KNRM << std::endl;
    std::string pr;
#ifdef KK_RSA4096
    pr = dir + "rsa4096_private" + std::to_string(id);
#endif
#ifdef KK_RSA2048
    pr = dir + "rsa2048_private" + std::to_string(id);
#endif
    FILE * fpr = fopen (pr.c_str(), "rb");

    if (fpr == NULL) {
        if (DEBUG) std::cout << KYEL << "Unable to open file " << pr << KNRM << std::endl;
        return 1;
    }
    *priv = PEM_read_RSAPrivateKey (fpr, priv, NULL, NULL);
    fclose(fpr);
    if (DEBUG) std::cout << KYEL << "loaded private key from " << pr << KNRM << std::endl;
    return 0;
}


int KeysFun::loadPublicKey(PROCESS_ID pid, RSA_key* pub) {
    // Loading public key
    if (DEBUG) std::cout << KMAG << "loading public key" << KNRM << std::endl;
    std::string pb;

#ifdef KK_RSA4096
    pb = dir + "rsa4096_public" + std::to_string(pid);
#endif
#ifdef KK_RSA2048
    pb = dir + "rsa2048_public" + std::to_string(pid);
#endif
    FILE * fpb = fopen (pb.c_str(), "rb");

    if (fpb == NULL) {
        if (DEBUG) std::cout << KYEL << "Unable to open file " << pb << KNRM << std::endl;
        return 1;
    }
    if (DEBUG) std::cout << KMAG << "loading key from " << pb << KNRM << std::endl;
    *pub = PEM_read_RSAPublicKey (fpb, pub, NULL, NULL);
    fclose(fpb);
    if (DEBUG) std::cout << KMAG << "loaded public key from " << pb << KNRM << std::endl;
    return 0;
}


int KeysFun::loadPrivateKey(PROCESS_ID id, EC_key* priv) {
    if (DEBUG) std::cout << KYEL << "loading private key" << KNRM << std::endl;
    std::string pr;
#ifdef KK_EC521
    pr = dir + "ec521_private" + std::to_string(id);
#endif
#ifdef KK_EC256
    pr = dir + "ec256_private" + std::to_string(id);
#endif
    FILE * fpr = fopen (pr.c_str(), "rb");

    if (fpr == NULL) {
        if (DEBUG) std::cout << KYEL << "Unable to open file " << pr << KNRM << std::endl;
        return 1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    pkey = PEM_read_PrivateKey(fpr, &pkey, NULL, NULL);

    *priv = EVP_PKEY_get1_EC_KEY(pkey);
    fclose(fpr);
    if (DEBUG) std::cout << KYEL << "loaded private key from " << pr << KNRM << std::endl;

    // free the pkey
    EVP_PKEY_free(pkey);

    return 0;
}


int KeysFun::loadPublicKey(PROCESS_ID id, EC_key* pub) {
    if (DEBUG) std::cout << KYEL << "loading public key" << KNRM << std::endl;
    std::string pb;
#ifdef KK_EC521
    pb = dir + "ec521_public" + std::to_string(id);
#endif
#ifdef KK_EC256
    pb = dir + "ec256_public" + std::to_string(id);
#endif
    FILE * fpb = fopen (pb.c_str(), "rb");

    if (fpb == NULL) {
        if (DEBUG) std::cout << KYEL << "Unable to open file " << pb << KNRM << std::endl;
        return 1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    pkey = PEM_read_PUBKEY(fpb, &pkey, NULL, NULL);

    *pub = EVP_PKEY_get1_EC_KEY(pkey);
    fclose(fpb);
    if (DEBUG) std::cout << KYEL << "loaded public key from " << pb << KNRM << std::endl;

    // free the pkey
    EVP_PKEY_free(pkey);

    return 0;
}


/*int KeysFun::loadPrivateKey(PROCESS_ID id, BLS_key* priv) {
    if (DEBUG) std::cout << KYEL << "loading private key" << KNRM << std::endl;
    std::string pr = dir + "bls_private" + std::to_string(id);

    // -- read private key
    std::ifstream t;
    t.open(pr);
    std::string line;
    std::getline(t, line);
    t.close();
    if (DEBUG) std::cout << KMAG << "read (from " << pr << "): " << line << KNRM << std::endl;

    // -- set element to be the private key read above
    int n = element_set_str(**priv, line.c_str(), 10);
    if (DEBUG) std::cout << KMAG << "got " << n << " elements" << KNRM << std::endl;

    return 0;
}*/


/*int KeysFun::loadPublicKey(PROCESS_ID id, BLS_key* pub) {
    if (DEBUG) std::cout << KYEL << "loading public key" << KNRM << std::endl;
    std::string pb = dir + "bls_public" + std::to_string(id);

    // -- read public key
    std::ifstream t;
    t.open(pb);
    std::string line;
    std::getline(t, line);
    t.close();
    if (DEBUG) std::cout << KMAG << "read (from " << pb << "): " << line << KNRM << std::endl;

    // -- set element to be the public key read above
    int n = element_set_str(**pub, line.c_str(), 10);
    if (DEBUG) std::cout << KMAG << "got " << n << " elements" << KNRM << std::endl;

    return 0;
}*/


void KeysFun::generateRsa4096Keys(int id) {
  //The pseudo-random number generator must be seeded prior to calling RSA_generate_key_ex function
  unsigned char seed[] = {0x58 ,0x48 ,0x54 ,0x4f ,0x36 ,0x65 ,0x69 ,0x47};
  RAND_seed(seed,8);

  RSA* rsa = RSA_new();//allocate empty key
  unsigned long e = RSA_F4 ; //65537 public exponent
  BIGNUM* bne = BN_new(); // allocate BINNUM structure in heap
  BN_set_word(bne,e); //store that public exponent in big-number object bne

  // generate RSA key with length 4096 , public exponent 65537
  RSA_generate_key_ex(rsa,NUM_BITS,bne,NULL);

  //allocate a memory BIO in heap
  BIO* bio_private = BIO_new(BIO_s_mem());
  BIO* bio_public  = BIO_new(BIO_s_mem());

  //extract private and public key to bio-object respectively
  PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);
  PEM_write_bio_RSAPublicKey(bio_public, rsa);

  //BIO_pending function return number of byte read to bio buffer during previous step
  int private_len = BIO_pending(bio_private);
  int public_len  = BIO_pending(bio_public);

  //this two buffer will hold the keys as string
  char* private_key = new char[private_len + 1];
  char* public_key  = new char[public_len + 1];

  //copy extracted keys to string
  BIO_read(bio_private, private_key, private_len);
  BIO_read(bio_public, public_key, public_len);

  //ensure that both keys ends with null terminator
  private_key[private_len]=0;
  public_key[public_len]=0;

  // std::cout << private_key << std::endl << std::endl << std::endl << std::endl;
  // std::cout << public_key  << std::endl << std::endl << std::endl << std::endl;

  std::string pr = dir + "private" + std::to_string(id);
  std::cout << "writing private key to " << pr << std::endl;
  std::ofstream priv;
  priv.open (pr);
  priv << private_key;
  priv.close();

  std::string pu = dir + "public" + std::to_string(id);
  std::cout << "writing public key to " << pu << std::endl;
  std::ofstream pub;
  pub.open (pu);
  pub << public_key;
  pub.close();

  //clean up memory
  RSA_free(rsa);
  BN_free(bne);
  BIO_free(bio_private);
  BIO_free(bio_public);
  delete [] private_key;
  delete [] public_key;
  RAND_cleanup();
}


void KeysFun::generateRsa2048Keys(int id) {
  //The pseudo-random number generator must be seeded prior to calling RSA_generate_key_ex function
  unsigned char seed[] = {0x58 ,0x48 ,0x54 ,0x4f ,0x36 ,0x65 ,0x69 ,0x47};
  RAND_seed(seed,8);

  RSA* rsa = RSA_new();//allocate empty key
  unsigned long e = RSA_F4 ; //65537 public exponent
  BIGNUM* bne = BN_new(); // allocate BINNUM structure in heap
  BN_set_word(bne,e); //store that public exponent in big-number object bne

  // generate RSA key with length 2048 , public exponent 65537
  RSA_generate_key_ex(rsa,NUM_BITS2,bne,NULL);

  //allocate a memory BIO in heap
  BIO* bio_private = BIO_new(BIO_s_mem());
  BIO* bio_public  = BIO_new(BIO_s_mem());

  //extract private and public key to bio-object respectively
  PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);
  PEM_write_bio_RSAPublicKey(bio_public, rsa);

  //BIO_pending function return number of byte read to bio buffer during previous step
  int private_len = BIO_pending(bio_private);
  int public_len  = BIO_pending(bio_public);

  //this two buffer will hold the keys as string
  char* private_key = new char[private_len + 1];
  char* public_key  = new char[public_len + 1];

  //copy extracted keys to string
  BIO_read(bio_private, private_key, private_len);
  BIO_read(bio_public, public_key, public_len);

  //ensure that both keys ends with null terminator
  private_key[private_len]=0;
  public_key[public_len]=0;

  // std::cout << private_key << std::endl << std::endl << std::endl << std::endl;
  // std::cout << public_key  << std::endl << std::endl << std::endl << std::endl;

  std::string pr = dir + "private" + std::to_string(id);
  std::cout << "writing private key to " << pr << std::endl;
  std::ofstream priv;
  priv.open (pr);
  priv << private_key;
  priv.close();

  std::string pu = dir + "public" + std::to_string(id);
  std::cout << "writing public key to " << pu << std::endl;
  std::ofstream pub;
  pub.open (pu);
  pub << public_key;
  pub.close();

  //clean up memory
  RSA_free(rsa);
  BN_free(bne);
  BIO_free(bio_private);
  BIO_free(bio_public);
  delete [] private_key;
  delete [] public_key;
  RAND_cleanup();
}


// based on http://fm4dd.com/openssl/eckeycreate.htm
void KeysFun::generateEc521Keys(int id) {
  BIO      *outbio = NULL;
  EC_KEY   *myecc  = NULL;
  EVP_PKEY *pkey   = NULL;
  int      eccgrp;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio = BIO_new(BIO_s_mem());

  /* ---------------------------------------------------------- *
   * Create a EC key sructure, setting the group type from NID  *
   * ---------------------------------------------------------- */
  eccgrp = OBJ_txt2nid("secp521r1");
  myecc = EC_KEY_new_by_curve_name(eccgrp);

  /* -------------------------------------------------------- *
   * For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
   * ---------------------------------------------------------*/
  EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

  /* -------------------------------------------------------- *
   * Create the public/private EC key pair here               *
   * ---------------------------------------------------------*/
  if (! (EC_KEY_generate_key(myecc)))
    std::cout << KMAG << "Error generating the ECC key" << KNRM << std::endl;

  /* -------------------------------------------------------- *
   * Converting the EC key into a PKEY structure let us       *
   * handle the key just like any other key pair.             *
   * ---------------------------------------------------------*/
  pkey=EVP_PKEY_new();
  if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
    std::cout << KMAG << "Error assigning ECC key to EVP_PKEY structure" << KNRM << std::endl;

  /* -------------------------------------------------------- *
   * Now we show how to extract EC-specifics from the key     *
   * ---------------------------------------------------------*/
  myecc = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

  /* ---------------------------------------------------------- *
   * Here we print the key length, and extract the curve type.  *
   * ---------------------------------------------------------- */
  std::cout << KMAG << "ECC Key size: " << EVP_PKEY_bits(pkey) << " bit" << KNRM << std::endl;
  std::cout << KMAG << "ECC Key type: " << OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)) << KNRM << std::endl;

  /* ---------------------------------------------------------- *
   * Here we print the private/public key data in PEM format.   *
   * ---------------------------------------------------------- */
  // --- private key
  if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
    std::cout << KMAG << "Error writing private key data in PEM format" << KNRM << std::endl;
  //BIO_pending function return number of byte read to bio buffer during previous step
  int private_len = BIO_pending(outbio);
  //std::cout << "private length: " << private_len << std::endl;
  char* private_key = new char[private_len + 1];
  BIO_read(outbio, private_key, private_len);
  private_key[private_len]=0;

  // --- public key
  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    std::cout << KMAG << "Error writing public key data in PEM format" << KNRM << std::endl;
  //BIO_pending function return number of byte read to bio buffer during previous step
  int public_len  = BIO_pending(outbio);
  //std::cout << "public length: " << public_len << std::endl;
  char* public_key  = new char[public_len + 1];
  BIO_read(outbio, public_key, public_len);
  public_key[public_len]=0;

  // printing keys to files
  std::string pr = dir + "ec_private" + std::to_string(id);
  std::cout << KMAG << "writing EC private key to " << pr << KNRM << std::endl;
  std::ofstream priv;
  priv.open (pr);
  priv << private_key;
  priv.close();

  std::string pu = dir + "ec_public" + std::to_string(id);
  std::cout << KMAG << "writing EC public key to " << pu << KNRM << std::endl;
  std::ofstream pub;
  pub.open (pu);
  pub << public_key;
  pub.close();

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  EVP_PKEY_free(pkey);
  EC_KEY_free(myecc);
  BIO_free_all(outbio);
}


// based on http://fm4dd.com/openssl/eckeycreate.htm
void KeysFun::generateEc256Keys(int id) {
  BIO      *outbio = NULL;
  EC_KEY   *myecc  = NULL;
  EVP_PKEY *pkey   = NULL;
  int      eccgrp;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio = BIO_new(BIO_s_mem());

  /* ---------------------------------------------------------- *
   * Create a EC key sructure, setting the group type from NID  *
   * ---------------------------------------------------------- */
  eccgrp = OBJ_txt2nid("prime256v1");
  myecc = EC_KEY_new_by_curve_name(eccgrp);

  /* -------------------------------------------------------- *
   * For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
   * ---------------------------------------------------------*/
  EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

  /* -------------------------------------------------------- *
   * Create the public/private EC key pair here               *
   * ---------------------------------------------------------*/
  if (! (EC_KEY_generate_key(myecc)))
    std::cout << KMAG << "Error generating the ECC key" << KNRM << std::endl;

  /* -------------------------------------------------------- *
   * Converting the EC key into a PKEY structure let us       *
   * handle the key just like any other key pair.             *
   * ---------------------------------------------------------*/
  pkey=EVP_PKEY_new();
  if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
    std::cout << KMAG << "Error assigning ECC key to EVP_PKEY structure" << KNRM << std::endl;

  /* -------------------------------------------------------- *
   * Now we show how to extract EC-specifics from the key     *
   * ---------------------------------------------------------*/
  myecc = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

  /* ---------------------------------------------------------- *
   * Here we print the key length, and extract the curve type.  *
   * ---------------------------------------------------------- */
  std::cout << KMAG << "ECC Key size: " << EVP_PKEY_bits(pkey) << " bit" << KNRM << std::endl;
  std::cout << KMAG << "ECC Key type: " << OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)) << KNRM << std::endl;

  /* ---------------------------------------------------------- *
   * Here we print the private/public key data in PEM format.   *
   * ---------------------------------------------------------- */
  // --- private key
  if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
    std::cout << KMAG << "Error writing private key data in PEM format" << KNRM << std::endl;
  //BIO_pending function return number of byte read to bio buffer during previous step
  int private_len = BIO_pending(outbio);
  //std::cout << "private length: " << private_len << std::endl;
  char* private_key = new char[private_len + 1];
  BIO_read(outbio, private_key, private_len);
  private_key[private_len]=0;

  // --- public key
  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    std::cout << KMAG << "Error writing public key data in PEM format" << KNRM << std::endl;
  //BIO_pending function return number of byte read to bio buffer during previous step
  int public_len  = BIO_pending(outbio);
  //std::cout << "public length: " << public_len << std::endl;
  char* public_key  = new char[public_len + 1];
  BIO_read(outbio, public_key, public_len);
  public_key[public_len]=0;

  // printing keys to files
  std::string pr = dir + "ec_private" + std::to_string(id);
  std::cout << KMAG << "writing EC private key to " << pr << KNRM << std::endl;
  std::ofstream priv;
  priv.open (pr);
  priv << private_key;
  priv.close();

  std::string pu = dir + "ec_public" + std::to_string(id);
  std::cout << KMAG << "writing EC public key to " << pu << KNRM << std::endl;
  std::ofstream pub;
  pub.open (pu);
  pub << public_key;
  pub.close();

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  EVP_PKEY_free(pkey);
  EC_KEY_free(myecc);
  BIO_free_all(outbio);
}


/*void KeysFun::generateBlsKeys(int id) {
  //element_t public_key;
  //element_t secret_key;
  //element_init_G2(public_key, pairing);
  //element_init_Zr(secret_key, pairing);


  // -- generating secret key
  element_random(secret_key); // generate random secret_key
  element_printf("private key %d = %B\n", id, secret_key);


  // -- compute corresponding public key
  //element_pow_zn(public_key, bls_g, secret_key); // compute public_key = g^secret_key
  //element_printf("public key %d = %B\n\n", id, public_key);


  std::string sec_str = dir + "bls_private" + std::to_string(id);
  std::string pub_str = dir + "bls_public"  + std::to_string(id);
  FILE *sec_file = fopen(sec_str.c_str(), "w");
  FILE *pub_file = fopen(pub_str.c_str(), "w");


  // -- Exporting private key
  std::cout << KMAG << "writing BLS private key to " << sec_str << KNRM << std::endl;
  element_out_str(sec_file, 10, secret_key);


  // -- Exporting public key
  std::cout << KMAG << "writing BLS public key to " << pub_str << KNRM << std::endl;
  element_out_str(pub_file, 10, public_key);


  // -- kleening
  fclose(sec_file);
  fclose(pub_file);
}*/


/*RSA_key newRSA() {
    RSA *key = RSA_new ();
    return key;
}*/


// TODO: don't we need to set the group and point?
// it looks like the commented out stuff are not needed...
/*EC_key newEC() {
    int eccgrp = OBJ_txt2nid("secp521r1");
    EC_KEY *key = EC_KEY_new_by_curve_name(eccgrp);
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    return key;
}*/

/*BLS_key newBLS(element_t key) {
    element_t key;
    return key;
}*/

/*KEY newKEY() {
#ifdef KK_RSA4096
  return newRSA();
#endif
#ifdef KK_RSA2048
  return newRSA();
#endif
#ifdef KK_EC521
  return newEC();
#endif
#ifdef KK_EC256
  return newEC();
#endif
#ifdef KK_BLS
  //newBLS(key);
#endif
}*/
