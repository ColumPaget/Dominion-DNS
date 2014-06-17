#ifndef DOMINION_CACHE_H
#define DOMINION_CACHE_H

#include "DNSMessage.h"
#include "Global.h"
#include "Modules.h"

#define NoOfCaches 4
typedef enum {CI_QUERY, CI_NS, CI_ACL, CI_DNSUPDATE} T_CI;

#define CACHE_ITEMS_EXPIRE 1

void CacheInit();
void CacheOpenAll();
void CacheLoadModule(ModuleStruct *CType, int);
int CacheAddDNSMessage(DNSMessageStruct *Item, int ItemType);
int CacheAddRR(ResourceRecord *Item, int ItemType);
int CacheDeleteRR(ResourceRecord *RR, int ItemType);
int CacheFindMatchRR(ResourceRecord *RR, int ItemType, ListNode *RRList);
int CacheFindMatchDNSMessage(DNSMessageStruct *Item, int ItemType, ListNode *RRList);


#endif
