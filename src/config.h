#ifndef CONFIG_H
#define CONFIG_H


// debug switches
#define DEBUG   false
#define DEBUG0  true
#define DEBUG1  false
#define DEBUG2  false
#define DEBUG3  false
#define DEBUG4  false
#define DEBUG5  false
#define DEBUG6  false
#define DEBUG7  false
#define DEBUG8  false
#define DEBUG9  false
#define DEBUG10 false
#define DEBUG11 false
#define DEBUG12 true
#define DEBUG13 false


#define MAX_NUM_SIGNATURES 50
#define NO_SOCKET          -1
#define MAXLINE            256
#define CONF_FILE_SIZE     250
#define NUM_BITS           4096
#define NUM_BITS2          2048


// MULTISIG must be defined to use multi-signatures
//   only in combination with BLS?
//#define MULTISIG

// Switch between different schemes:
// - KK_NO       --- no signatures
// - KK_RSA4096  --- RSA_4096 signatures
// - KK_RSA2048  --- RSA_2048 signatures
// - KK_EC521    --- elliptic curve signatures
// - KK_EC256    --- elliptic curve signatures
// - KK_BLS      --- BLS signatures
//#define KK_NO
//#define KK_RSA2048
//#define KK_BLS
#define KK_EC256
//#define KK_EC521


#ifdef KK_NO
  #define SIGN_LEN 0   // NO
#endif
#ifdef KK_RSA4096
  #define SIGN_LEN 512 // RSA_4096
#endif
#ifdef KK_RSA2048
  #define SIGN_LEN 256 // RSA_2048
#endif
#ifdef KK_EC521
  #define SIGN_LEN 139 // EC_521
#endif
#ifdef KK_EC256
  #define SIGN_LEN 71 // EC_256
#endif
#ifdef KK_BLS
  #define SIGN_LEN 260 // BLS
#endif



// ----------------------------------------
// Colors
// ------

#define KNRM  "\x1B[0m"

// default background & different foreground colors
#define KRED  "\x1B[49m\x1B[31m"
#define KGRN  "\x1B[49m\x1B[32m"
#define KYEL  "\x1B[49m\x1B[33m"
#define KBLU  "\x1B[49m\x1B[34m"
#define KMAG  "\x1B[49m\x1B[35m"
#define KCYN  "\x1B[49m\x1B[36m"
#define KWHT  "\x1B[49m\x1B[37m"

// default background & different (light) foreground colors
#define KLRED  "\x1B[49m\x1B[91m"
#define KLGRN  "\x1B[49m\x1B[92m"
#define KLYEL  "\x1B[49m\x1B[93m"
#define KLBLU  "\x1B[49m\x1B[94m"
#define KLMAG  "\x1B[49m\x1B[95m"
#define KLCYN  "\x1B[49m\x1B[96m"
#define KLWHT  "\x1B[49m\x1B[97m"

// diferent background colors & white foreground
#define KBRED  "\x1B[41m\x1B[37m"
#define KBGRN  "\x1B[42m\x1B[37m"
#define KBYEL  "\x1B[43m\x1B[37m"
#define KBBLU  "\x1B[44m\x1B[37m"
#define KBMAG  "\x1B[45m\x1B[37m"
#define KBCYN  "\x1B[46m\x1B[37m"
#define KBWHT  "\x1B[47m\x1B[30m"

#endif
