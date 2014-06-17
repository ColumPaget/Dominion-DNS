#ifndef DOMINION_MODULES_H
#define DOMINION_MODULES_H

#include "DNSMessage.h"

/* This file is the interface and definition file for functions concerning  */
/* runtime loadable modules. There are three types of modules currently     */
/* supported. 

	1) Lookup Modules. These implement code to query various files or
	other sources to answer DNS queries.

	2) Cache Modules. These implement different types of 'Cache' in order
	to store information retrieved from external sources locally.

	3) Monitor Modules. These allow special behavoir to be taken on
	receipt of a request for information. The most obvious example being
	to log each request.
*/


extern ListNode *ModuleSettings;
typedef struct mod_struct ModuleStruct;

typedef void (*MOD_INIT_FUNC)(ModuleStruct *);
typedef int (*MOD_ADD_RR_FUNC)(ModuleStruct *, ResourceRecord *);
typedef int (*MOD_DEL_RR_FUNC)(ModuleStruct *, ResourceRecord *);
typedef int (*MOD_SEARCH_FUNC)(ModuleStruct *, ResourceRecord *, ListNode *RRList);

struct mod_struct
{
int Flags;
char *Name;
char *ModulePath;
MOD_INIT_FUNC Open;
MOD_ADD_RR_FUNC AddRR;
MOD_DEL_RR_FUNC DelRR;
MOD_SEARCH_FUNC Search;
int DefaultTTL, MaxTTL;
int ReloadTime;
char *Path;
time_t LastReload;
uint32_t ShortestLookup;
uint32_t LongestLookup;
uint32_t Lookups;
uint32_t Hits;
uint32_t ItemsInCache;
uint16_t LookupTimes[20];
void *Implementation;
};


void LoadModule(ModuleStruct *);
ModuleStruct *CreateModuleStruct();

#endif

