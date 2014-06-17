
#include "URL.h"
#include "ACL.h"
#include "Cache.h"
#include "Global.h"


int GetACLRecords(char *Key, ListNode *Answers, int PermType, int CurrResult, int Auth)
{
ResourceRecord *RR, *FoundRR;
ListNode *Curr;
int result=CurrResult;

RR=CreateRR(Key,"",0,9999,PermType,CLASS_INTERNET);
CacheFindMatchRR(RR,CI_ACL,Answers);

Curr=ListGetNext(Answers);
while(Curr !=NULL)
{
   FoundRR=(ResourceRecord *) Curr->Item;
   if (strcmp(FoundRR->Answer,"allow")==0) result=DOMAIN_ALLOW;
   else if (strcmp(FoundRR->Answer,"allow-local")==0) result=DOMAIN_ALLOW_LOCAL;
   else if ( (strcmp(FoundRR->Answer,"allow-auth")==0) && Auth) result=DOMAIN_ALLOW;
   else if ( (strcmp(FoundRR->Answer,"allow-local-auth")==0) && Auth) result=DOMAIN_ALLOW_LOCAL;
   else result=DOMAIN_DENY;
   Curr=ListGetNext(Curr);
}

DestroyRR(RR);
return(result);
}


/* This function goes thru the permissions list and decides if this host */
/* is allowed to query the nameserver. There are three possible return   */
/* values, deny, allowlocal, and allow.                                  */

/*
int CheckACL(DNSMessageStruct *Query, int PermType, int Auth)
{
int result;
ListNode *Answers=NULL;
char *ptr, *checkstr;

result=DOMAIN_ALLOW;

Answers=ListCreate();
result=GetACLRecords("*", Answers, PermType, result, Auth);
ListDestroy(Answers,DestroyRR);


ptr=ClientName+StrLen(ClientName)-1;
while (ptr >= ClientName)
{
checkstr=NULL;
if (*ptr=='.') checkstr=ptr+1;
else if (ptr==ClientName) checkstr=ptr;

if (checkstr)
{
  Answers=ListCreate();
  result=GetACLRecords(checkstr, Answers, PermType, result, Auth);
  ListDestroy(Answers,DestroyRR);
}

ptr--;
}

return(result);
}
*/


int CheckACL(char *Question, char *AuxData, int PermType, int Auth)
{
ResourceRecord *RR, *FoundRR;
ListNode *Curr, *Answers;
int result=DOMAIN_ALLOW, len;
char *ptr, *checkstr;

len=StrLen(Question);
if (len==0) return(FALSE);

Answers=ListCreate();
ptr=Question+StrLen(Question)-1;
while (ptr >= Question)
{
  checkstr=NULL;
  if (*ptr=='.') checkstr=ptr+1;
  else if (ptr==Question) checkstr=ptr;

  if (checkstr)
  {
    RR=CreateRR(checkstr,"",0,9999,PermType,CLASS_INTERNET);
    CacheFindMatchRR(RR,CI_ACL,Answers);
    DestroyRR(RR);
  }

  ptr--;
}


Curr=ListGetNext(Answers);
while(Curr !=NULL)
{
   FoundRR=(ResourceRecord *) Curr->Item;
   if (
	   (
	    	(PermType==PT_CLIENT) ||
	    	(PermType==PT_UPDATE)
	   ) &&
	   (strcasecmp(Question,FoundRR->Answer)==0)
      )
   {
	if (strcmp(FoundRR->Answer,"allow")==0) result=DOMAIN_ALLOW;
   	else if (strcmp(FoundRR->Answer,"allow-local")==0) result=DOMAIN_ALLOW_LOCAL;
   	else if ( (strcmp(FoundRR->Answer,"allow-auth")==0) && Auth) result=DOMAIN_ALLOW;
   	else if ( (strcmp(FoundRR->Answer,"allow-local-auth")==0) && Auth) result=DOMAIN_ALLOW_LOCAL;
   	else if (strcmp(FoundRR->Answer,"log")==0) LogToFile(Settings.LogFilePath,"%s",AuxData);
   	else if (strcmp(FoundRR->Answer,"syslog")==0) syslog(LOG_INFO,"%s",AuxData);
   	else if (strcmp(FoundRR->Answer,"deny")==0) result=DOMAIN_DENY;
   }

   if (
	   (PermType==PT_URL) &&
	   (strcasecmp(Question,FoundRR->Answer)==0)
      )
   {
	if (strcmp(FoundRR->Answer,"allow")==0) result=DOMAIN_ALLOW;
	else if (strcmp(FoundRR->Answer,"log")==0) LogToFile(Settings.LogFilePath,"%s",AuxData);
   	else if (strcmp(FoundRR->Answer,"syslog")==0) syslog(LOG_INFO,"%s",AuxData);
 
   	else if (strcmp(FoundRR->Answer,"deny")==0) result=DOMAIN_DENY;
   }
   
   Curr=ListGetNext(Curr);
}

ListDestroy(Answers,DestroyRR);
return(result);

}
