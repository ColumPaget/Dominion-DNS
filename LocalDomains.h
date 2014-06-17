#ifndef DOM_LOCAL_DOMAINS_H
#define DOM_LOCAL_DOMAINS_H

#include "Global.h"

DomainEntryStruct *FindLocalDomainForName(char *Name, int Authority);
DomainEntryStruct *FindLocalDomainForAddress(unsigned long Address);
int IsLocalDomainName(char *Name);
int IsLocalDomainAddress(unsigned long Address);

#endif
