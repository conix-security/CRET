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
#include "head.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Send buffer on hpipe, after xoring each byte with XORBYTE, returns WriteFile return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL sendCrypt(HANDLE hpipe,char* buffer,int buflen,PDWORD lenSent,LPOVERLAPPED useless)
{
	int i;
	for(i =0; i<buflen; i++)
		buffer[i]=buffer[i]^XORBYTE;

	return WriteFile(hpipe,buffer,buflen,lenSent,useless);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Receive buffer on hpipe, xor each byte with XORBYTE, returns ReadFile return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL recvCrypt(HANDLE hpipe,char* buffer, int buflen,PDWORD lenRecvd,LPOVERLAPPED useless)
{
	unsigned int i;
	BOOL data = ReadFile(hpipe,buffer,buflen,lenRecvd,useless);
	
	if(!data)
		return data;
	for(i =0; i<*lenRecvd; i++)
		buffer[i]=buffer[i]^XORBYTE;

	return data;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Starts dynamic communication. Creates a pipe to communicate, displays data received on the
//		pipe, and sends keyboard input (only when \r is pressed, in order to handle backspace issues).
//
//		Error messages start with the ![?E0X pattern where "X" is the error code.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void dynamic(char* username, char* password, char* target, char* command, char* args, bool file)
{
	HANDLE hpipe;
	DWORD ret2;
	char buffer[1024];
	char bufferS[1024];
	char* targetpipe;
	char* newcommand;
	char* bye;
	char t;
	size_t len = 0;
	size_t pipelen = 0;
	ULONG read;
	BOOL runnin;
	ULONG avail;
	ULONG exit=0;
	int cpt=0;
	DWORD lastTime;

	lastTime = GetTickCount();

	//generate the command line :
	//[X|B]command args
	if(args != NULL)
		len = strlen(args);

	len=1+strlen(command)+1+len+1;
	newcommand = (char*)malloc(sizeof(char)*(len));
	if(file)
		newcommand[0]='B';
	else
		newcommand[0]='X';

	newcommand[1] = 0x00;
	strcat_s(newcommand,len,command);
	if(args != NULL)
	{
		strcat_s(newcommand,len," ");
		strcat_s(newcommand,len,args);
	}
	pipelen = strlen(target)+14;
	targetpipe = (char*)malloc(sizeof(char)*(pipelen));
	strcpy_s(targetpipe,pipelen,target);
	strcat_s(targetpipe,pipelen,PIPENAME);

	printf("\t[-] Connecting to remote service... ");
	ret2 = mapShare(username,password,target);
	if(ret2!=0 && ret2!=0x4c3) //error or already connected
		printf("fail (0x%x)\n",ret2);
	
	hpipe = CreateFileA(targetpipe,GENERIC_ALL,FILE_SHARE_WRITE,NULL,OPEN_EXISTING,SECURITY_ANONYMOUS,NULL);
	if( hpipe == INVALID_HANDLE_VALUE )
    {
		printf("fail. Aborting...\n");
		free(targetpipe);
		unmapShare(target);
		return;
	}
	else
	{
		printf(" OK.\n\n");

		//command
		sendCrypt(hpipe,newcommand,strlen(newcommand),&ret2,NULL);
		FlushFileBuffers(hpipe);

		runnin = true;
		while(runnin)
		{
			memset(buffer,0,1024);

			PeekNamedPipe(hpipe,buffer,1023,&read,&avail,NULL);
			if(read != 0)
			{
				memset(buffer,0,1024);
				if(avail > 1023)
				{
					while(read >= 1023)
					{
						recvCrypt(hpipe,buffer,1023,&read,NULL);

						//error messages
						if(buffer[0]=='!' && buffer[1]=='[' && buffer[2]=='?'  && buffer[3]=='E')
						{
							switch(buffer[4])
							{
								case '1':
									printf("\n\t[!] Error: impossible to create communication pipes, aborting...\n");
									runnin = false;
									break;
								case '2':
									printf("\n\t[!] Error: impossible to create communication pipes, aborting...\n");
									runnin = false;
									break;
								case '3':
									printf("\n\t[!] Error: impossible to spawn the process, aborting...\n");
									runnin = false;
									break;
								case '4':
									printf("\n\t[!] Error: transmission error, aborting...\n");
									runnin = false;
									break;
								case '5':
									printf("\n\t[!] Error: read error.\n");
								case '0':
									if(read > 5)
									{
										printf("%s",(char*)(buffer+5));
									}
									printf("\n\n[-] Program execution finished!\n");
									runnin = false;
									break;
								default:
									printf("%s",buffer);
									break;
							}
							

							if(read > 5)
								printf("%s",(char*)(buffer+5));
						}
						else
						{
							//exit code
							bye = strstr(buffer,"![?E0");
							if(bye != NULL)
							{
								bye[0]=0x00;
								printf("%s\n\n[-] Program execution finished!\n",buffer);
								runnin = false;
							}
							else
								printf("%s",buffer);
						}
						memset(buffer,0,1024);
					}
				}
				else
				{
					recvCrypt(hpipe,buffer,1023,&read,NULL);

					//error messages
					if(buffer[0]=='!' && buffer[1]=='[' && buffer[2]=='?'  && buffer[3]=='E')
					{
						switch(buffer[4])
						{
							case '1':
								printf("\n\t[!] Error: impossible to create communication pipes, aborting...\n");
								runnin = false;
								break;
							case '2':
								printf("\n\t[!] Error: impossible to create communication pipes, aborting...\n");
								runnin = false;
								break;
							case '3':
								printf("\n\t[!] Error: impossible to spawn the process, aborting...\n");
								runnin = false;
								break;
							case '4':
								printf("\n\t[!] Error: transmission error, aborting...\n");
								runnin = false;
								break;
							case '5':
								printf("\n\t[!] Error: read error.\n");
							case '0':
								if(read > 5)
								{
									printf("%s",(char*)(buffer+5));
								}
								printf("\n\n[-] Program execution finished!\n");
								runnin = false;
								break;
							default:
								printf("%s",buffer);
								break;
						}
						
						if(read > 5)
							printf("%s",(char*)(buffer+5));
					}
					else
					{
						//exit code
						bye = strstr(buffer,"![?E0");
						if(bye != NULL)
						{
							bye[0]=0x00;
							printf("%s\n\n[-] Program execution finished!\n",buffer);
							runnin = false;
						}
						else
							printf("%s",buffer);
					}
				}
			}

			//check stdin
			if(_kbhit())
			{
				bufferS[cpt] = (char)_getche();
				t = bufferS[cpt];
				cpt ++;

				if(bufferS[cpt-1] == '\r')
				{
					printf("\n");
					bufferS[cpt]='\n';
					sendCrypt(hpipe,bufferS,cpt+1,&read,NULL);
					FlushFileBuffers(hpipe);
					cpt=0;
				}
				else if(bufferS[cpt-1] == 0x8)	// backspace
				{
					printf(" \b");
					cpt=cpt-2;
				}
			}
		}
		CloseHandle(hpipe);
	}
	free(newcommand);
	free(targetpipe);
	unmapShare(target);
}
