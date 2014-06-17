#ifndef DOM_DNS_ENTRY_H
#define DOM_DNS_ENTRY_H

/* This file concerns the most basic data type in the DNS server, one that   */
/* stores data related to either a hostname or a domain name that we know of */

typedef struct
{
char *Name;
unsigned long Address;
unsigned long TTL;

}DNSEntryStruct;


DNSEntryStruct *CreateDNSEntry(char *Name, unsigned long *IPAddr);
void *DestroyDNSEntry(DNSEntryStruct *);

#endif



