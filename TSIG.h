#ifndef DOMINION_TSIG_H
#define DOMINION_TSIG_H
#include "Global.h"

typedef struct
{
int KeyType;
char *KeyName;
char *KeyValue;
int KeyLength;
}TSigKey;


int HandleTSIG(char *NameData, int TsigOffset, int CurrOffset, char *KeyName, unsigned int TTL, int RDataLen, char *EndOfMessage,DNSMessageStruct *);

#endif

