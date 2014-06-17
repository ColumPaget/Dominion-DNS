#ifndef DOMINION_SETTINGS_H
#define DOMINION_SETTINGS_H

#include "std_include.h"

#define FLAG_USE_CACHE 1
#define FLAG_BLOCK_REVERSE_LOOKUPS 2
#define FLAG_SHORTNAMES_LOCAL 4
#define FLAG_REF_AUTH 8
#define FLAG_SLAVE_MODE 16
#define FLAG_NODEMON 32
#define FLAG_FORCE_TTL 64
#define FLAG_CLIENTLOGS 128


typedef struct 
{
unsigned int Flags;
unsigned long Interface;
unsigned short Port;
ListNode *ResolveOrderList;
ListNode *SigKeyList;
ListNode *BindMounts;
char *CacheModName;
char *ChRoot;
char *ConnectionLog;
char *RunAsUser;
char *RunAsGroup;
char *LogDir;
char *LogFilePath;
int ConfigReadTime;
int DefaultTTL;
int ForceDefaultTTL;
int MultiQuery;
int LogLevel;
int SyslogLevel;
int MaxLogSize;
} SettingsStruct;

#endif
