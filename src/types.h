#ifndef TYPES_H
#define TYPES_H

#include <set>
#include <list>
#include <vector>

enum unit { tt };

enum PHASE {
  PHASE_ECHO,
  PHASE_DELIVER,
};

enum STATUS {
  STATUS_ACTIVE,
  STATUS_PASSIVE,
  STATUS_RECOVERING,
};

enum MODE {
  MODE_BROADCAST,
  MODE_ECHO,
  MODE_DELIVER,
};

enum HEADER {
  HDR_BROADCAST,
  HDR_ECHO,
  HDR_DELIVER,
  HDR_START,
  HDR_DIFFUSE,
  HDR_TIMEOUT,
  HDR_RECOVER,
  HDR_ACTIVE,
  HDR_TRANSFER,
};

typedef unsigned int PROCESS_ID;
typedef unsigned int SEQUENCE_NUM;
typedef unsigned long int LOCTIME;

typedef PROCESS_ID PID;
typedef std::set<PROCESS_ID> PIDS;
typedef std::list<PROCESS_ID> PIDL;
typedef std::vector<PROCESS_ID> PIDV;


#endif
