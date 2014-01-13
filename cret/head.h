// Copyright 2013 Conix Security, Adrien Chevalier
// adrien.chevalier@conix.fr
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#ifndef HEAD_H
#define HEAD_H

#include <windows.h>
#include <stdio.h>
#include <Winnetwk.h>
#include <comdef.h>
#include <conio.h>
#include <Wbemidl.h>

#define CRED_MAX_USERNAME_LENGTH (256+1+256)
#define CREDUI_MAX_USERNAME_LENGTH  CRED_MAX_USERNAME_LENGTH
#define SERVICENAME "CRETSVC"
#define EXECNAME "CRETSVC.exe"
#define XORBYTE 0xCC
#define PIPENAME "\\pipe\\cretsvc"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Startup, parse args and starts processing.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char** argv);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Help display.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void help();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Maps the "target" remote share with "username" credentials.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD mapShare(char* username, char* password, char* target);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unmap a remote share.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void unmapShare(char* target);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs and starts remote service on "target".
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD startRemoteService(char* path, char* target);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Uninstalls (after stopping) the remote service.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD uninstallRemoteService(char* target);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sends WMI command to target after logging on.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD startWMICommand(char* command, char* target, char* username, char* password);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Starts dynamic communication. Creates a pipe to communicate, displays data received on the
//		pipe, and sends keyboard input (only when \r is pressed, in order to handle backspace issues).
//
//		Error messages start with the ![?E0X pattern where "X" is the error code.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void dynamic(char* username, char* password, char* target, char* command, char* args, bool file);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Receive buffer on hpipe, xor each byte with XORBYTE, returns ReadFile return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL recvCrypt(HANDLE hpipe,char* buffer, int buflen,PDWORD lenRecvd,LPOVERLAPPED useless);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Send buffer on hpipe, after xoring each byte with XORBYTE, returns WriteFile return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL sendCrypt(HANDLE hpipe,char* buffer,int buflen,PDWORD lenSent,LPOVERLAPPED useless);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Extract the service resource onto \\computer\admin$
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD write_resource(char* path, char* computer);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Copy path to remoteShare, overwrite if flag set and returns the new filename.
//		NB : the returned char* size is MAX_PATH*sizeof(char) and must be free by the caller.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
char* copyFileToRemoteShareAndGetFileName(char* path, char* remoteShare, bool overwrite);

#endif