#include "Global.h"
#include "URL.h"
#include "LocalDomains.h"

DomainEntryStruct *FindLocalDomainForName(char *Name, int Authority)
{
DomainEntryStruct *Domain, *LastMatch;
ListNode *Curr, *NSList;
int result=DOMAIN_REMOTE;

// if we have been given a nameserver that specifically services this domain
// then we consider it not a local domain
NSList=ListCreate();
if (LookupNameServers(Name, DNSREC_NAMESERVER, NSList)) 
{
ListDestroy(NSList,DestroyRR);
return(NULL);
}
ListDestroy(NSList,DestroyRR);

Curr=ListGetNext(LocalDomainsListHead);
while (Curr !=NULL)
{
     Domain=(DomainEntryStruct *) Curr->Item;

     if (DomainNameCompare(Name,Domain->Name)) 
     {
	if ((! Authority) || (Domain->Flags & DOMAIN_AUTH))
        {
          result=Domain->Flags;
          LastMatch=Domain;
          break;
	}
     }
     Curr=ListGetNext(Curr);
}
if (result & DOMAIN_LOCAL) return(LastMatch);
return(NULL);
}


DomainEntryStruct *FindLocalDomainForAddress(unsigned long Address)
{
DomainEntryStruct *Domain, *LastMatch;
ListNode *Curr;
int result;

Curr=ListGetNext(LocalDomainsListHead);
while (Curr !=NULL)
{
  Domain=(DomainEntryStruct *) Curr->Item;
  if (!Domain) continue;

  if (AddressCompare(Address,Domain->Address)) 
  {
    result=Domain->Flags;
    LastMatch=Domain;

    /* If we break here then we can let the user have a system of     */
    /* 'fall-thru' domains, for instance, they can set the last local */
    /* domain to be 'none 0.0.0.0', this is useful if you set up      */
    /* clients with a 'search order' of "none", so that they don't    */
    /* cause trouble with queries to addresses that they have produced*/
    /* by appending the default domain to the name requested.         */
    break;
  }
  Curr=ListGetNext(Curr);
}

if (result==DOMAIN_LOCAL) return(LastMatch);
return(NULL);
}



int IsLocalDomainName(char *Name)
{
if (FindLocalDomainForName(Name, FALSE) !=NULL) return(TRUE);
return(FALSE);
}



int IsLocalDomainAddress(unsigned long Address)
{
if (FindLocalDomainForAddress(Address) !=NULL) return(TRUE);
return(FALSE);
}
