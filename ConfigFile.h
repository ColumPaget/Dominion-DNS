#ifndef DOM_CONFIG_FILE_H
#define DOM_CONFIG_FILE_H
#include <stdio.h> /*for the definition of NULL */
#include "Global.h"


void ReadConfigFile(char *, SettingsStruct *);
void DestroyDomainEntryArray(DomainEntryStruct **);
void AddDomainItemToList(ListNode *,char *, char *, int);
void ReloadConfigFile();

#endif
