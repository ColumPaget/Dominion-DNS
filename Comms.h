#ifndef DOM_COMMS_H
#define DOM_COMMS_H

#include "DNSMessage.h"
#include "Global.h"


int SendQuery(ConnectStruct *Con, char *Server, DNSMessageStruct *Query);
void SendResponse(ConnectStruct *Con,DNSMessageStruct *Response,SettingsStruct *);
void SendNotFoundResponse(ConnectStruct *Con, DNSMessageStruct *Response, SettingsStruct *);

#endif
