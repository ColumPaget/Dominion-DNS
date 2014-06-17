
#define DEFAULT_WINS_PATH "/var/lock/samba/wins.dat"

#include "../DNSMessage.h"
#include "../Modules.h"
#include "../Global.h"
#include "../LocalDomains.h"
#include "../URL.h"
#include <stdio.h>
#include <time.h>





int WinsFileQuery(ModuleStruct *Mod, char *SearchName,DNSMessageStruct *Query)
{
int found=FALSE;
STREAM *S;
char *Line=NULL, *ptr1, *ptr2, *LineEnd;
/*Search Key is either the Required name, or the Required Address*/
char *SearchKey=NULL, *FoundName=NULL, *ExpireTimeStr=NULL, *FoundAddr=NULL;
DomainEntryStruct *RequiredDomain;
ResourceRecord *NewRR;
time_t ExpireTime;
char *FileName;
int count;


if ((Now-Mod->LastReload) > 10)
{
STREAMClose((STREAM *) Mod->Implementation);
Mod->Implementation=(void *) STREAMOpenFile(Mod->Path,O_RDONLY);
Mod->LastReload=Now;
}

S=(STREAM *) Mod->Implementation;

SearchKey=CopyStr(SearchKey,Query->Question);

/* The hosts in the WINS file lack fully qualified domain names, the domain */
/* bit is missing, so we need to clip the domain name off the name we are   */
/* looking for, but this means we need to check later on that the Address   */
/* the name we have found is contained within the domain we were looking for*/
if (Query->Type != DNSREC_DOMAINNAME) 
{
	ptr1=strchr(SearchKey,'.');
	if (ptr1) *ptr1='\0';
}

while(! found)
{
Line=STREAMReadLine(Line,S);
if (! Line) break;

StripTrailingWhitespace(Line);

ptr1=Line;

/* the last item in the record is I know not what, but I don't want to be */
/* concerned with it, so I chop it off here, giving me just               */
/* <Name> <ExpireTime> <Address1> <Address2> ...                          */
ptr2=strrchr(Line,' ');
if (ptr2) *ptr2=0;


/* Get the hostname */
ptr1=GetToken(ptr1," ",&FoundName,0);

/* Clear some bits and bobs off the name*/
ptr2=(char *)strchr(FoundName,'#');
if (ptr2) *ptr2=0;
memmove(FoundName,FoundName+1, strlen(FoundName));

/* Check for wins cache corruption, seems to happen quite often! */
for (count=0; count < strlen(FoundName); count++)
{
  if (! isprint(FoundName[count])) continue;
}

/* Get the expire time*/
if (ptr1)
{
ptr1=GetToken(ptr1," ",&ExpireTimeStr,0);
}
else continue; 


/* if this entry is expired then get the next record*/
ExpireTime=atoi(ExpireTimeStr);
if (ExpireTime < Now)
{
    continue;
}


/*From now on its all IP addresses*/
while (ptr1)
{
  ptr1=GetToken(ptr1," ",&FoundAddr,0);


  /* If this entry matches and has not expired then we use it */
  if ( Query->Type==DNSREC_DOMAINNAME)
  {
    if (strcmp(FoundAddr,Query->Question)==0)
    {
       RequiredDomain=FindLocalDomainForAddress(StrtoIP(FoundAddr));
       if (RequiredDomain !=NULL)
       {
         NewRR=CreateRR(SearchName,FoundName,0,ExpireTime-Now,DNSREC_DOMAINNAME,CLASS_INTERNET);
         /*Stick the domain on the end of the name*/
         NewRR->Answer=CatStr(NewRR->Answer,".");
         NewRR->Answer=CatStr(NewRR->Answer,RequiredDomain->Name);
         ListAddItem(Query->Answers,NewRR);
         Query->NoOfAnswers++;
         found=TRUE;

       }

    }
  }
  else if(strcasecmp(FoundName,SearchKey)==0) 
  {
  /* So we've found a name that matches, but now we must check if it is for */
  /* the same domain as the name we want, by comparing addresses            */
    RequiredDomain=FindLocalDomainForAddress(StrtoIP(FoundAddr));
    if ((RequiredDomain != NULL) && 
        (strcmp(RequiredDomain->Name,ExtractDomainName(Query->Question))==0))
    {
      NewRR=CreateRR(Query->Question,FoundAddr,0,ExpireTime-Now,DNSREC_ADDRESS,CLASS_INTERNET);
      ListAddItem(Query->Answers,NewRR);
      Query->NoOfAnswers++;
      found=TRUE;
    }
  }

}
}

DestroyString(Line);
DestroyString(SearchKey);
DestroyString(FoundName);
DestroyString(FoundAddr);
DestroyString(ExpireTimeStr);

return(found);
}



void WinsFileOpen(ModuleStruct *Mod)
{
if (! StrLen(Mod->Path)) Mod->Path=CopyStr(Mod->Path,DEFAULT_WINS_PATH);
Mod->Implementation=(void *) STREAMOpenFile(Mod->Path,O_RDONLY);
Mod->LastReload=Now;


if (Mod->Implementation ==NULL) LogToFile(Settings.LogFilePath,"ERROR: Unable to open WINS file %s",Mod->Path);
else LogToFile(Settings.LogFilePath,"LOOKUP SOURCE: WINS file at %s",Mod->Path);
}

void ModuleInit(ModuleStruct *Mod)
{
Mod->Open=WinsFileOpen;
Mod->Search=WinsFileQuery;
}

