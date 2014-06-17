
#define DEFAULT_HOSTS_PATH "/etc/hosts"

#include "../Global.h"
#include "../DNSMessage.h"

#include "../Modules.h"
#include <stdio.h>
#include <string.h>
#include "../Cache.h"





int ParseHostsLine(char *Line,char **HostAddr,char **FullName, char **ShortName)
{
	char inchar;
	char *ptr1, *ptr2;

	*HostAddr=CopyStr(*HostAddr,"");
	*FullName=CopyStr(*FullName,"");
	*ShortName=CopyStr(*ShortName,"");
	ptr1=Line;
	ptr1=GetToken(ptr1,"\\S", HostAddr,0);
	if (!ptr1) return(FALSE);
	ptr1=GetToken(ptr1,"\\S", FullName,0);
	if (!ptr1) return(FALSE);
	ptr1=GetToken(ptr1,"\\S", ShortName,0);

	return(TRUE);

}


int HostsFileQuery(ModuleStruct *LS, char *SearchName,DNSMessageStruct *Query)
{
static STREAM *S=NULL;
char *Line=NULL;
char *HostAddr=NULL, *FullName=NULL, *ShortName=NULL;
char *Answer;
ResourceRecord *RR;
int result=FALSE;
char *FileName=DEFAULT_HOSTS_PATH;


/*We can only answer Address Queries and DNSREC_DOMAINNAME Queries from the */
/*hosts file. */
if ((Query->Type !=DNSREC_ADDRESS) && (Query->Type !=DNSREC_DOMAINNAME) ) return(FALSE);

FileName=LS->Path;
if (FileName==NULL)  return(FALSE); 

S=(STREAM *) LS->Implementation;

Line=CopyStr(Line,"");
HostAddr=CopyStr(HostAddr,"");
FullName=CopyStr(FullName,"");
ShortName=CopyStr(ShortName,"");

STREAMSeek(S,0,SEEK_SET);
Line=STREAMReadLine(Line,S);
while(Line)
{
StripTrailingWhitespace(Line);
StripLeadingWhitespace(Line);
if ((StrLen(Line) > 0) && (Line[0] != '#'))
{
  ParseHostsLine(Line,&HostAddr,&FullName,&ShortName);

  if ( 
     ( (Query->Type==DNSREC_ADDRESS) && (strcasecmp(FullName,SearchName)==0) ) ||
     ( (Query->Type==DNSREC_ADDRESS) && (strcasecmp(ShortName,SearchName)==0) ) ||
     ( (Query->Type==DNSREC_DOMAINNAME) && (strcasecmp(HostAddr,SearchName)==0) ) 
     )
    {
LogToFile(Settings.LogFilePath,"HostsCmp [%s] [%s] [%s]",FullName,ShortName,SearchName);
      if (Query->Type==DNSREC_ADDRESS) Answer=HostAddr;
      else Answer=FullName;

      Query->NoOfAnswers++;
      RR=CreateRR(SearchName,Answer,0,999,Query->Type,CLASS_INTERNET);
      ListAddItem(Query->Answers,RR);
      result=TRUE;
      Query->Header.AuthAns=TRUE;
    }
}
Line=STREAMReadLine(Line,S);
}

DestroyString(Line);
DestroyString(HostAddr);
DestroyString(FullName);
DestroyString(ShortName);
return(result);

}


int CacheLoadHostsFile(ModuleStruct *LS)
{
static STREAM *S=NULL;
char *Line=NULL;
char *HostAddr=NULL, *FullName=NULL, *ShortName=NULL;
ResourceRecord *RR;
int result=FALSE;
char *FileName=DEFAULT_HOSTS_PATH;

FileName=LS->Path;
if (FileName==NULL)  return(FALSE); 

S=(STREAM *) LS->Implementation;

Line=CopyStr(Line,"");
HostAddr=CopyStr(HostAddr,"");
FullName=CopyStr(FullName,"");
ShortName=CopyStr(ShortName,"");


STREAMSeek(S,0,SEEK_SET);
Line=STREAMReadLine(Line,S);
while(Line)
{
StripTrailingWhitespace(Line);
StripLeadingWhitespace(Line);

if ((StrLen(Line) > 0) && (Line[0] !='#'))
{
  ParseHostsLine(Line,&HostAddr,&FullName,&ShortName);
  RR=CreateRR(FullName,HostAddr,0,LS->DefaultTTL,DNSREC_ADDRESS,CLASS_INTERNET);
  CacheAddRR(RR,CI_QUERY);
  DestroyRR(RR);
}

Line=STREAMReadLine(Line,S);
}

DestroyString(Line);
DestroyString(HostAddr);
DestroyString(FullName);
DestroyString(ShortName);
return(result);
}

void HostsFileOpen(ModuleStruct *Mod)
{
if (! StrLen(Mod->Path)) Mod->Path=CopyStr(Mod->Path,DEFAULT_HOSTS_PATH);
Mod->Implementation=STREAMOpenFile(Mod->Path,O_RDONLY);

if (! Mod->Implementation) LogToFile(Settings.LogFilePath,"ERROR: Unable to open hosts file %s",Mod->Path);
else LogToFile(Settings.LogFilePath,"LOOKUP SOURCE: Hosts file at %s",Mod->Path);
}



void ModuleInit(ModuleStruct *Mod)
{
Mod->Open=HostsFileOpen;
Mod->Search=HostsFileQuery;
//Mod->CacheLoad=CacheLoadHostsFile;
}
