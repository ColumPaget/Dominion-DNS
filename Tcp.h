#ifndef DOMINION_TCP_H
#define DOMINION_TCP_H

#include "Global.h"

void TCPDestroyConnection(ConnectStruct *Con);
void TCPAcceptConnection(int ServerSock);
int TCPAddSocksToSelect(fd_set *ReadSet, fd_set *WriteSet);
void TCPCheckConnections(fd_set *SelectSet, SettingsStruct *Settings, ConnectStruct *RemoteCon);

#endif
