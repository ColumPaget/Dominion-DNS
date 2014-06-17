#ifndef RemoteDNSServers_H
#define RemoteDNSServers_H

#include "DNSMessage.h"
#include "Global.h"
#include "Modules.h"

typedef struct
{
time_t LastQueryTime;
time_t QueryStartTime;
int NoOfServersQueried;
ConnectStruct *ClientCon;
ConnectStruct *ServerCon;
DNSMessageStruct *QueryData;
ListNode *ServersForThisQuery;
ListNode *CurrServer;
} QueryQueueItem;

extern ModuleStruct *RemoteStats;
void HandleServerConnected(ConnectStruct *ServerCon);

#endif
