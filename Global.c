#include "Global.h"
#include <sys/stat.h>

ListNode *QueryListHead;
SettingsStruct Settings;


ListNode *LocalDomainsListHead;
ListNode *AliasListHead;
ListNode *LookupSourceList;
ListNode *TrustedCacheUpdateSourceList;
ListNode *UpdatesSendList;

char *G_DialupLinkName;
char *G_ConfigFilePath;
char *G_DomFilePath;
int G_DialupLinkTimeout;
int G_MaxCacheSize;
char *G_LinkTimeoutScript;
char *G_NoServersScript;

time_t DominionStartTime;
time_t Now;

unsigned int fnv_hash ( void *key, int len )
{
  unsigned char *p = key;
  unsigned int h = 2166136261;
  int i;

  for ( i = 0; i < len; i++ ) h = ( h * 16777619 ) ^ p[i];

 return(h);
}


void DestroyDomainEntry(void *inptr)
{
if (! inptr) return;
DestroyString(((DomainEntryStruct *) inptr)->Name);
free(inptr);
}


