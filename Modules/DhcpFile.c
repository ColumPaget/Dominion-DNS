#include "../Modules.h"
#include "../Global.h"
#include <stdio.h>
#include "../DNSMessage.h"
#include "../Modules.h"

#define DEFAULT_DHCP_PATH "/var/lib/dhcp/dhcpd.leases"

void InitModule(ModuleStruct *);



/* The functions in this section involve the dhcpd.leases file, and reading */
/* information from it concerning the Names/Addresses of hosts. Note, that  */
/* because this file contains a 'history' of the leases that have been given*/
/* out we cannot assume that the first match we find is the correct one, we */
/* must search the entire file and treat the last match that we find as the */
/* one that we want.                                                        */



int GetWordFromFile(STREAM *InFile, char **Buffer)
{
int len=0;
int inchar; //this is so that the next line always reads once

*Buffer=CopyStr(*Buffer,"");

inchar=STREAMReadChar(InFile);
switch (inchar)
{
case EOF: return(FALSE); break;

//Comment, consume the data and return a blank line
case '#': 
	while ((inchar !=EOF) && (inchar !='\n')) inchar=STREAMReadChar(InFile);
	return(TRUE);
break;

case ' ': 
case '	': 
	while (isspace(inchar)) inchar=STREAMReadChar(InFile);
break;
}


while((inchar !=EOF) && (! isspace(inchar)) )
{
	*Buffer=AddCharToBuffer(*Buffer,len,inchar);
	len++;
	inchar=STREAMReadChar(InFile);
}

return(TRUE);
}



/* This checks if a mac address to hostname map has been specified.*/
/* If so it copies the specified name into place */

char *CheckForMacAlias(char *NameStr, char *MacStr)
{
ListNode *Curr;
char *ptr;
char *tempstr=NULL, *FoundStr=NULL;

if (StrLen(MacStr)==0) return;
/*
FoundStr=CopyStr(NameStr,"");
Curr=ListGetNext(ModuleSettings);
while (Curr)
{
CurrSetting=(ModuleSettingsStruct *) Curr->Item;
if ((CurrSetting->Name) && (strcasecmp(CurrSetting->Name,"MacAddressToName")==0))
{
  ptr=GetToken(CurrSetting->Value," ",&tempstr,0);
  if (strcasecmp(tempstr,MacStr)==0)
  {
    ptr=GetToken(ptr,"\n",&FoundStr,0);
  }
}

Curr=ListGetNext(Curr);
}
*/

DestroyString(tempstr);
return(FoundStr);
}


time_t ConvertDateStrToSecs(char *DateStr)
{
struct tm TM;
int result;

result=strptime(DateStr,"%Y/%m/%d %H:%M:%S",&TM);
if (result==-1) strptime(DateStr,"%d/%m/%Y %H:%M:%S",&TM);
return(mktime(&TM));
}


int ReadLeaseData(STREAM *LeaseFile,ResourceRecord *RR)
{
char *DateStr=NULL, *Buffer=NULL;
int result=FALSE, val;
char *ptr;

RR->Question=CopyStr(RR->Question,"");
RR->Answer=CopyStr(RR->Answer,"");
result=GetWordFromFile(LeaseFile,&Buffer);
while(result)
{

  if (strcmp(Buffer,"lease")==0)    /* found a 'lease' line,     */
  {                                 /* next word will be IP addr */
    GetWordFromFile(LeaseFile,&Buffer);
    RR->Answer=CopyStr(RR->Answer,Buffer);
  }

  if (strcmp(Buffer,"client-hostname")==0)  
  {
    /* Get Hostname */
    GetWordFromFile(LeaseFile,&Buffer);

    /*name is surrounded by quotes, remove these*/
    ptr=strrchr(Buffer,'"');
    if (ptr) *ptr=0;

    ptr=Buffer;
    while ((*ptr=='"') || isspace(*ptr)) ptr++;
    RR->Question=CopyStr(RR->Question,ptr);
  }

  if (strncmp(Buffer,"hardware",9)==0)  
  {
    /* Get 'ethernet' */
    GetWordFromFile(LeaseFile,&Buffer);
    /* Get Mac Address */
    GetWordFromFile(LeaseFile,&Buffer);
    ptr=Buffer+StrLen(Buffer) -1;
    if (*ptr==';') *ptr='\0';
    RR->Ptr=CopyStr(RR->Ptr,Buffer);

  }

  if (strncmp(Buffer,"ends",9)==0)  
  {
    /* Get 'mysterious number' */
    GetWordFromFile(LeaseFile,&Buffer);
    /* Get date */
    GetWordFromFile(LeaseFile,&Buffer);
    DateStr=CopyStr(DateStr,Buffer);
    DateStr=CatStr(DateStr," ");
     /* Get Time */
    GetWordFromFile(LeaseFile,&Buffer);
    DateStr=CatStr(DateStr,Buffer);
    ptr=DateStr+StrLen(DateStr) -1;
    if (*ptr==';') *ptr='\0';

	val=ConvertDateStrToSecs(DateStr)-Now;
	if (val > 0) RR->TTL=(unsigned long) val;
  }

  if (strcmp(Buffer,"}")==0) break;

   result=GetWordFromFile(LeaseFile,&Buffer);
 }



DestroyString(DateStr);
DestroyString(Buffer);

return(result);
}


int DhcpFileQuery(ModuleStruct *Mod, char *SearchName, DNSMessageStruct *Query)
{
STREAM *LeasesFile;
ResourceRecord *RR=NULL, *BestAnswer=NULL;
int result=FALSE;
DomainEntryStruct *RequiredDomain;
char *MacAlias=NULL;

if ((Now-Mod->LastReload) > 10)
{
STREAMClose((STREAM *) Mod->Implementation);
Mod->Implementation=(void *) STREAMOpenFile(Mod->Path,O_RDONLY);
Mod->LastReload=Now;
}

LeasesFile=(STREAM *) Mod->Implementation;
STREAMSeek(LeasesFile,0,SEEK_SET);

/*we can only answer Address Queries or DNSREC_DOMAINNAME Queries from the dhcp*/
/*leases file. */
if ((Query->Type !=DNSREC_ADDRESS) && (Query->Type !=DNSREC_DOMAINNAME)) return(FALSE);

RR=CreateRR("","",0,20,Query->Type,CLASS_INTERNET);
BestAnswer=CreateRR("","",0,20,Query->Type,CLASS_INTERNET);

if (LeasesFile==NULL) 
{
	if (Settings.LogLevel) LogToFile(Settings.LogFilePath,"ERROR: Cannot open dhcp leases file %s",Mod->Path);
}
else
{

/*ReadLeaseData returns the found Hostname as the RR->Question, and the */
/*found Address as RR->Answer */

BestAnswer->Question=CopyStr(BestAnswer->Question,SearchName);
while(ReadLeaseData(LeasesFile,RR))
{

    /* if this mac address maps to a hostname then get that */
        RequiredDomain=FindLocalDomainForAddress(StrtoIP(RR->Answer));



        if (RequiredDomain !=NULL)
        {
             RR->Question=CatStr(RR->Question,".");
             RR->Question=CatStr(RR->Question,RequiredDomain->Name);
         }

    //MacAlias=CheckForMacAlias(MacAlias,(char *) RR->Ptr);

    if ((StrLen(MacAlias) > 0) && (strcasecmp(SearchName,MacAlias)==0))
    {
	 RR->Question=CopyStr(RR->Question,MacAlias);
    }
    RR->Ptr=DestroyString(RR->Ptr);

   if (
        (
         (Query->Type==DNSREC_ADDRESS) &&
         (strcasecmp(RR->Question,SearchName)==0)
         )
      ||
        (
         (Query->Type==DNSREC_DOMAINNAME) &&
         (strcasecmp(RR->Answer,SearchName)==0)
        )
      )
      {
	if (RR->TTL > BestAnswer->TTL)
	{
        if (Query->Type==DNSREC_ADDRESS) BestAnswer->Answer=CopyStr(BestAnswer->Answer,RR->Answer);
        else BestAnswer->Answer=CopyStr(BestAnswer->Answer,RR->Question);
	BestAnswer->TTL=RR->TTL;
	}
        result=TRUE;
      }


}
}

DestroyString(MacAlias);

if (RR) DestroyRR(RR);
if (result)
{
  ListAddItem(Query->Answers,BestAnswer);
  Query->NoOfAnswers++;
  return(TRUE);
}
else DestroyRR(BestAnswer);
return(FALSE);

}


void DhcpFileOpen(ModuleStruct *Mod)
{
if (! StrLen(Mod->Path)) Mod->Path=CopyStr(Mod->Path, DEFAULT_DHCP_PATH);
Mod->Implementation=(void *) STREAMOpenFile(Mod->Path,O_RDONLY);
Mod->LastReload=Now;

if (! Mod->Implementation) LogToFile(Settings.LogFilePath,"ERROR: Unable to open dhcp file %s",Mod->Path);
else  LogToFile(Settings.LogFilePath,"LOOKUP SOURCE: Dhcp file at %s",Mod->Path);
}


void ModuleInit(ModuleStruct *Mod)
{
Mod->Open=DhcpFileOpen;
Mod->Search=DhcpFileQuery;
}
