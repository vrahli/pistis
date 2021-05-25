
cplusplus {{
	#include "config.h"
	#include "types.h"
	#include "Sign.h"
	#include "Value.h"
	#include "Aggregate.h"
}};

enum HEADER;
class noncobject PROCESS_ID;
class noncobject SIGN;
class noncobject SEQUENCE_NUM;
class noncobject VALUE;
class noncobject Aggregate;
enum MODE;

packet BroadcastMsg
{
  int hdr @enum(HEADER);
  PROCESS_ID pid;
  SEQUENCE_NUM seq;
  VALUE val;
  Aggregate esign;
  Aggregate sign;
  int mode @enum(MODE);
  int inst;
  int round;
  //MODE mode;
}
