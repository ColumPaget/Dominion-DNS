#include "Manage.h"
#include "Global.h"


FILE *manageF;

void InitManage()
{
manageF=fopen("/tmp/dom.man","wt");
}



void WriteManage(char *Name, char *Value)
{
fseek(manageF,0,SEEK_SET);
fprintf(manageF,"%s = %s\n",Name,Value);
}
