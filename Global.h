#ifndef DOM_GLOBAL_H
#define DOM_GLOBAL_H



#include "std_include.h"
#include "LogLevels.h"
#include "Settings.h"
#include <stdio.h>
#include <string.h>


#ifdef STATIC_LINKED_CACHE
#include "Cache.h"
#endif

#include "Modules.h"



#define DOMAIN_ALLOW 0
#define DOMAIN_DENY 1
#define DOMAIN_ALLOW_LOCAL 2

#define DOMAIN_LOCAL 1
#define DOMAIN_REMOTE 2
#define DOMAIN_AUTH 4
#define UPDATE_CACHE_SIMPLE 8
#define UPDATE_ZONE_PUSH 16
#define REQUIRE_TSIG 32
#define REQUIRE_SSL 64

#define PENDING -1
#define FALSE 0
#define TRUE 1

#define UDP_MSG_LEN 1024
#define UDP_CONNECT 0
#define TCP_CONNECT 1


#define LOG_QUERIES 1
#define LOG_UPDATES 2
#define LOG_DENIALS 4
#define LOG_FINDS 8

/* Log levels, these don't go in general functions, because I'm probably going*/
/* to use those logging functions elsewhere, where these log levels will be   */
/* meaningless                                                                */


/* This is here because I cannot at this time decide where to put it. In the */
/* long term this struct is probaby going to be replaced by a more generic   */
/* system anyway.                                                            */
typedef struct 
{
char *Name;
uint32_t Address;
uint16_t Port;
int Flags;
} DomainEntryStruct;



#define USE_UDP 0
#define USE_TCP 1
#define USE_SSL 2


#define SERVER 0
#define CLIENT 1
#define CON_CLOSED 0
#define CON_INIT   1
#define CON_CONNECTED 2
#define CON_AUTH 3

typedef struct
{
int fd;
int Type;
int Direction;
int State;
char *PeerName;
time_t LastActivity;
struct sockaddr_in sa;
int MsgLen;
int BytesRead;
char *Buffer;
} ConnectStruct;

unsigned int fnv_hash ( void *key, int len );


char *GetModuleSetting(char *Name);
void DestroyDomainEntry(void *);

/*Ugh! a global variable, oh well, just the one*/
extern SettingsStruct Settings;
extern ListNode *QueryListHead;

extern ListNode *LocalDomainsListHead;
extern ListNode *AliasListHead;
extern ListNode *LookupSourceList;
extern ListNode *TrustedCacheUpdateSourceList;
extern ListNode *UpdatesSendList;


extern char *G_DialupLinkName;
extern char *G_ConfigFilePath;
extern char *G_DomFilePath;
extern int G_DialupLinkTimeout;
extern int G_MaxCacheSize;
extern char *G_LinkTimeoutScript;
extern char *G_NoServersScript;

extern time_t DominionStartTime;
extern time_t Now;
#endif
