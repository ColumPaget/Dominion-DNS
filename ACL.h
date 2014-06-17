#ifndef DOMINION_ACL_H
#define DOMINION_ACL_H


typedef enum {PT_CLIENT, PT_URL, PT_UPDATE} PermTypes;
int CheckACL(char *ClientName, char *AuxData, int PermType, int Auth);

#endif
