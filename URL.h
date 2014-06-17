#ifndef DOM_URL_H
#define DOM_URL_H

#include "Global.h"

void ExtractMachineName(char *, char *);
char *ExtractDomainName(char *);
char *IPtoStr(unsigned long);
unsigned long StrtoIP(char *);
int DomainNameCompare(char *, char *);
int AddressCompare(unsigned long, unsigned long);
int CheckHostPermission(ListNode*, char *,int);

#endif
