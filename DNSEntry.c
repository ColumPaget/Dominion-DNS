#include "DNSEntry.h"
#include "ResourceRecord.h"




DNSEntryStruct *CreateDNSEntry(char *Name, unsigned long IPAddr, unsigned long TTL)
{
DNSEntryStruct *Entry;

Entry=(DNSEntryStruct *) calloc(1,sizeof(DNSEntryStruct));
Entry.Name=(char *) CopyStr(Entry.Name,Name);
Entry.Address=IPAddr;
Entry.TTL=TTL;
return(Entry);

}


void DestroyDNSEntry(DNSEntryStruct *Entry)
{
free(Entry.Name);
free(Entry);

}
