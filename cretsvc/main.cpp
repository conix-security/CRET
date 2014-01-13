// Copyright 2013 Conix Security, Adrien Chevalier
// adrien.chevalier@conix.fr
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// defines
#define BUFSIZE 512
#define SERVICENAME "CRETSVC"
#define PIPENAME "\\\\.\\pipe\\cretsvc"
#define XORBYTE 0xCC
#define TIMEOUT 600000		// 10 minutes timeout

// functions
SERVICE_STATUS_HANDLE hsc;
BOOL sendCrypt(HANDLE hpipe,char* buffer,int buflen,PDWORD lenSent,LPOVERLAPPED useless);
BOOL recvCrypt(HANDLE hpipe,char* buffer, int buflen,PDWORD lenRecvd,LPOVERLAPPED useless);
VOID WINAPI handler(DWORD fdwControl);
int start(bool service);
int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow);
VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Send buffer on hpipe, after xoring each byte with XORBYTE, returns WriteFile return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL sendCrypt(HANDLE hpipe,char* buffer,int buflen,PDWORD lenSent,LPOVERLAPPED useless)
{
	for(int i =0; i<buflen; i++)
		buffer[i]=buffer[i]^XORBYTE;

	return WriteFile(hpipe,buffer,buflen,lenSent,useless);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Receive buffer on hpipe, xor each byte with XORBYTE, returns ReadFile return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL recvCrypt(HANDLE hpipe,char* buffer, int buflen,PDWORD lenRecvd,LPOVERLAPPED useless)
{
	BOOL data = ReadFile(hpipe,buffer,buflen,lenRecvd,useless);
	if(!data)
		return data;
	for(DWORD i =0; i<*lenRecvd; i++)
		buffer[i]=buffer[i]^XORBYTE;

	return data;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Service startup.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	
	SERVICE_STATUS status;

	status.dwCurrentState=SERVICE_RUNNING;
	status.dwWin32ExitCode=NO_ERROR;
	status.dwWaitHint=0;
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
	status.dwServiceSpecificExitCode = 0;
	status.dwControlsAccepted= SERVICE_ACCEPT_STOP;

	hsc=RegisterServiceCtrlHandler(SERVICENAME,&handler);
	SetServiceStatus(hsc,&status);

	start(true);
	return;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		WinMain.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	 SERVICE_TABLE_ENTRY DispatchTable[] = 
	{ 
		{ SERVICENAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain }, 
		{ NULL, NULL } 
	}; 
	if(strstr(lpCmdLine,"--service"))
	{
		StartServiceCtrlDispatcher(DispatchTable);
		return 0;
	}

	return start(false);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Service commands generic handler.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WINAPI handler(DWORD fdwControl)
{
	SERVICE_STATUS status;
	if(fdwControl==SERVICE_CONTROL_STOP)
	{
		status.dwCurrentState=SERVICE_STOPPED;
		status.dwWin32ExitCode=NO_ERROR;
		status.dwWaitHint=0;
		SetServiceStatus(hsc,&status);
		ExitProcess(0);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Main function, "service" if running into service mode.
//		Receives and executes commands, redirect stdin/stdout on the named pipe if dynamic mode is
//		enabled.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int start(bool service)
{
	BOOL ret;
	char* charz,* command,* args, *arguments;
	bool movin;
	size_t len;
	char cmd[]="cmd.exe";
	ULONG read,exit,avail,size;
	STARTUPINFOA si;
	DWORD lastTimeOut;
	SECURITY_ATTRIBUTES sa;
	PROCESS_INFORMATION pi;
	HANDLE hpipe,newstdin,newstdout,write_stdin,read_stdout,newstderr,write_stdintmp,read_stdouttmp;

	//process data
	ZeroMemory( &si, sizeof(STARTUPINFOA) );
	ZeroMemory( &pi, sizeof(PROCESS_INFORMATION) );
	si.wShowWindow = SW_HIDE;
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
	sa.lpSecurityDescriptor = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = true;  //allow inheritable handles

	command = (char*)malloc(sizeof(char)*256);
	charz = (char*)malloc(sizeof(char)*256);

	memset(charz,0,256);
	memset(command,0,256);

	//main loop (wait for pipe connection)
	while(1)
	{
		hpipe = CreateNamedPipeA(PIPENAME,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,0,PIPE_UNLIMITED_INSTANCES,BUFSIZE,BUFSIZE,0,NULL);
		if(hpipe == INVALID_HANDLE_VALUE)
		{
			if(service)
				handler(SERVICE_CONTROL_STOP);
			return -1;
		}
		ret = ConnectNamedPipe(hpipe,NULL);
		if(ret)
		{
			//read the command
			recvCrypt(hpipe,command,256,&size,NULL);

			if(command[0]=='B')
			{
				command = command +1;
				//parse the command (file.exe args)
				args = strstr(command," ");
				//if args : binary file + args (if any)
				if(args != NULL)
				{
					args[0] = 0x00;
					args = args +1;
				}
			}
			else
			{
				//command line
				arguments = command +1;
				//strip cmd.exe
				if(!_stricmp(arguments,"cmd") || !_stricmp(arguments,"cmd.exe"))
				{
					command = cmd;
					args = NULL;
				}
				else if(strstr(arguments,"cmd ")==arguments || strstr(arguments,"cmd.exe ")==arguments)
				{
					//strip cmd.exe
					if(strstr(arguments, "cmd ")==arguments)
						args = arguments+4;
					else
						args = arguments+8;

					command = cmd;
				}
				else
				{
					len = 3+strlen(arguments)+1;
					args = (char*)malloc(sizeof(char)*(len));
					strcpy_s(args,len,"/c ");
					strcat_s(args,len,arguments);
					command = cmd;
				}
			}

			

			//Create 2 pipes for stdin/stdout handling
			if(!CreatePipe(&newstdin,&write_stdintmp,&sa,0))
			{
				sprintf_s(charz,256,"![?E1");
				sendCrypt(hpipe,charz,5,&read,NULL);
				CloseHandle(hpipe);
				free(command);
				if(service)
					handler(SERVICE_CONTROL_STOP);
				return -1;
			}
			if(!CreatePipe(&read_stdouttmp,&newstdout,&sa,0))
			{
				CloseHandle(newstdin);
				CloseHandle(write_stdintmp);
				sprintf_s(charz,256,"![?E2");
				sendCrypt(hpipe,charz,5,&read,NULL);
				CloseHandle(hpipe);
				free(command);
				if(service)
					handler(SERVICE_CONTROL_STOP);
				return -1;
			}
			//duplicate stdout for stderr
			if (!DuplicateHandle(GetCurrentProcess(),newstdout,
                           GetCurrentProcess(),&newstderr,0,
                           TRUE,DUPLICATE_SAME_ACCESS))
			{
				CloseHandle(newstdin);
				CloseHandle(write_stdintmp);
				CloseHandle(newstdout);
				CloseHandle(read_stdouttmp);
				sprintf_s(charz,256,"![?E2");
				sendCrypt(hpipe,charz,5,&read,NULL);
				CloseHandle(hpipe);
				free(command);
				if(service)
					handler(SERVICE_CONTROL_STOP);
				return -1;
			}

			//make new copies, uninheritables
			if (!DuplicateHandle(GetCurrentProcess(),write_stdintmp,
				GetCurrentProcess(),
				&write_stdin,	// Address of new handle.
				0,FALSE,	// Make it uninheritable.
				DUPLICATE_SAME_ACCESS))
			{
				CloseHandle(newstdin);
				CloseHandle(write_stdintmp);
				CloseHandle(newstdout);
				CloseHandle(read_stdouttmp);
				sprintf_s(charz,256,"![?E2");
				sendCrypt(hpipe,charz,5,&read,NULL);
				CloseHandle(hpipe);
				free(command);
				if(service)
					handler(SERVICE_CONTROL_STOP);
				return -1;
			}
			if (!DuplicateHandle(GetCurrentProcess(),read_stdouttmp,
				GetCurrentProcess(),
				&read_stdout,	// Address of new handle.
				0,FALSE, 	// Make it uninheritable.
				DUPLICATE_SAME_ACCESS))
			{
				CloseHandle(newstdin);
				CloseHandle(write_stdintmp);
				CloseHandle(write_stdin);
				CloseHandle(newstdout);
				CloseHandle(read_stdouttmp);
				sprintf_s(charz,256,"![?E2");
				sendCrypt(hpipe,charz,5,&read,NULL);
				CloseHandle(hpipe);
				free(command);
				if(service)
					handler(SERVICE_CONTROL_STOP);
				return -1;
			}

			CloseHandle(write_stdintmp);
			CloseHandle(read_stdouttmp);
			
			//redirect stdin/stdout/stderr through pipes
			si.hStdError = newstderr;
			si.hStdOutput = newstdout;
			si.hStdInput = newstdin;

			//OutputDebugStringA(command);	//debug
			//OutputDebugStringA(args);	//debug
			//create process
			if (!CreateProcessA(command,args,NULL,NULL,TRUE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi))
			{
				CloseHandle(newstdin);
				CloseHandle(newstdout);
				CloseHandle(newstderr);
				CloseHandle(read_stdout);
				CloseHandle(write_stdin);
				sprintf_s(charz,256,"![?E3");
				sendCrypt(hpipe,charz,5,&read,NULL);
				CloseHandle(hpipe);
				free(command);
				free(charz);
				if(service)
					handler(SERVICE_CONTROL_STOP);
				return -1;
			}

			CloseHandle(newstdin);
			CloseHandle(newstdout);
			CloseHandle(newstderr);

			lastTimeOut = GetTickCount();

			//second loop : receiving and sending data
			while(1)
			{
				movin =false;

				//remote data (stdin)
				PeekNamedPipe(hpipe,charz,255,&read,&avail,NULL);
				if(read!=0)
				{
					memset(charz,0,256);
					if(avail > 255)
					{
						while(read >= 255)
						{
							if(recvCrypt(hpipe,charz,255,&read,NULL))
							{
								WriteFile(write_stdin,charz,read,&read,NULL);
							}
						}
					}
					else
					{
						if(recvCrypt(hpipe,charz,255,&read,NULL))
						{
							WriteFile(write_stdin,charz,read,&read,NULL);
						}
					}
					movin = true;
					lastTimeOut = GetTickCount();	//timeout
				}

				//local data (stdout)
				PeekNamedPipe(read_stdout,charz,255,&read,&avail,NULL);
				if(read != 0)
				{
					memset(charz,0,256);
					if(avail > 255)
					{
						while(read >= 255)
						{
							if(ReadFile(read_stdout,charz,255,&read,NULL))
								sendCrypt(hpipe,charz,read,&read,NULL);
							else
							{
								sprintf_s(charz,256,"![?E5");
								sendCrypt(hpipe,charz,5,&read,NULL);
							}
						}
					}
					else
					{
						if(ReadFile(read_stdout,charz,255,&read,NULL))
							sendCrypt(hpipe,charz,read,&read,NULL);
						else
						{
							sprintf_s(charz,256,"![?E5");
							sendCrypt(hpipe,charz,5,&read,NULL);
						}
					}
					movin = true;
				}

				// no activity (10 minutes) => exit
				if(!movin)
				{
					if(GetTickCount()-lastTimeOut > TIMEOUT)
					{
						TerminateProcess(pi.hProcess,0);
						CloseHandle(write_stdin);
						CloseHandle(read_stdout);
						CloseHandle(hpipe);
						free(command);
						free(charz);
						if(service)
							handler(SERVICE_CONTROL_STOP);
						return 0;
					}
				}

				if(!movin)
					Sleep(100);

				//process exit
				GetExitCodeProcess(pi.hProcess,&exit);
				if (exit != STILL_ACTIVE)
				{
					PeekNamedPipe(read_stdout,charz,255,&read,&avail,NULL);
					if(read != 0)
					{
						memset(charz,0,256);
						if(avail > 255)
						{
							while(read >= 255)
							{
								ReadFile(read_stdout,charz,255,&read,NULL);
								//printf("%s",charz);
								sendCrypt(hpipe,charz,read,&read,NULL);
							}
						}
						else
						{
							ReadFile(read_stdout,charz,255,&read,NULL);
							//printf("%s",charz);
							sendCrypt(hpipe,charz,read,&read,NULL);
						}
					}
					break;
				}
			}

			//the end
			sprintf_s(charz,256,"![?E0");
			sendCrypt(hpipe,charz,5,&read,NULL);
			CloseHandle(write_stdin);
			CloseHandle(read_stdout);
			CloseHandle(hpipe);
			free(command);
			free(charz);
			break;
		}
		else
			CloseHandle(hpipe);

		Sleep(500);
	}
	free(command);
	if(service)
		handler(SERVICE_CONTROL_STOP);
	return 0;
}

