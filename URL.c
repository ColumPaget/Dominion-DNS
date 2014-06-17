#include "URL.h"
#include "Global.h"
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/**** This file contains functions relating to both domain/host names and ****/
/**** IP Addresses. Hence the chosen name of the file may be a bit mis-   ****/
/**** leading. Alternative suggestions are welcome.                       ****/



char *ExtractDomainName(char *FullName)
{
char *tempptr;


tempptr=strchr(FullName,'.');
if (!tempptr) return("");
tempptr++;
return(tempptr);
}


/* This is a simple function to decide if a string is an IP address as   */
/* opposed to a host/domain name.                                        */

int IsAddress(char *Str)
{
int len,count;
len=strlen(Str);
if (len <1) return(FALSE);
for (count=0; count < len; count++)
   if ((! isdigit(Str[count])) && (Str[count] !='.')) return(FALSE);
 return(TRUE);
}




char *IPtoStr(unsigned long Address)
{
struct sockaddr_in sa;
sa.sin_addr.s_addr=Address;
return(inet_ntoa(sa.sin_addr));
}

unsigned long StrtoIP(char *Str)
{
struct sockaddr_in sa;
if (inet_aton(Str,&sa.sin_addr)) return(sa.sin_addr.s_addr);
return(0);
}




/* In some other DNS servers fully qualified domain names are written       */
/* backwards, in keeping with the 'black magick' feel of DNS. This makes it */
/* simple to calculate if somehost.somedomain.com matches *.somedomain.com, */
/* or *.*.com etc. I've chosen to use a function that does a backwards      */
/* strcmp instead. This function then checks if www.foobar.com is in the    */
/* domain foobar.com. This function will return true if you compare         */
/* www.foobar.com against itself, or against .foobar.com, otherwise false.  */ 

int DomainNameCompare(char *CompareThis, char *CompareAgainstThis)
{
int len1, count, len2;

if ((CompareThis==NULL) || (CompareAgainstThis==NULL)) return(FALSE);
len1 = strlen(CompareAgainstThis);
len2 = strlen(CompareThis);

if ((len1==0) || (len2==0)) return(FALSE);
if (len2 < len1) return(FALSE);

for (count=1; count <=len1; count++)
{
if (tolower(CompareThis[len2-count]) != tolower(CompareAgainstThis[len1-count]))
                                       break;

}

/* we didn't find any difference but we must now check that we are either   */
/* comparing identical names, or ones that are the same up to a domain '.'  */
if ((count > len1) && ((len1==len2) || (CompareThis[len2-count]=='.')))
{
return(TRUE);
}
 return(FALSE);
}


int AddressCompare(unsigned long CompareThis, unsigned long CompareAgainstThis)
{
int count;
unsigned long mask, result, SubNetMask=0;

/* first if they are equal then there you go !*/
if (CompareThis==CompareAgainstThis) return(TRUE);


/*This only works for subnets of the types 255.0.0.0, 255.255.0.0 and      */
/* 255.255.255.0 and 255.255.255.255 (which is pointless)                  */

mask =255;
for (count=0; count <4; count++)
{
result=CompareAgainstThis & mask;
if (result) SubNetMask=SubNetMask | mask;
mask=mask << 8;
}
if ((CompareThis & SubNetMask) == CompareAgainstThis) return(TRUE);

return(FALSE);
}




