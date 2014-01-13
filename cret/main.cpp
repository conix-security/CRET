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
//		Startup, parse args and starts processing.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char** argv)
{
	//temp
	int i = 0;
	char* servname;
	ULONG servnameLen = strlen(EXECNAME)+24;

	//main parameters
	char* computer = NULL;
	char* fullDriveName = NULL;
	char* username = NULL;
	char* fullUsername = NULL;
	char* password = NULL;
	char* command = NULL;
	char* args = NULL;
	char* path = NULL;
	char* fileName;
	char* ptrstr;
	bool file = false;
	bool standalone = false;
	bool overwrite = true;		//true : do not overwrite (CopyFileA(X,X,overwrite))
	bool cleanTraces = false;
	bool useService = false;
	DWORD returnValue = 0;
	size_t len = 0;



//################################################################
//	PARSE ARGUMENTS
//################################################################

	for(i=1;i<argc;i=i+1)
	{
		if(argv[i][0]=='-')
		{
			switch(argv[i][1])
			{
				case 'h':
					help();
					return 0;
					break;
				case 'c':
					if(i+1<argc)
						computer = argv[i+1];
					i=i+1;
					break;
				case 'u':
					if(i+1<argc)
						username = argv[i+1];
					i=i+1;
					break;
				case 'p':
					if(i+1<argc)
						password = argv[i+1];
					i=i+1;
					break;
				case 'x':
					if(i+1<argc)
						command = argv[i+1];
					i=i+1;
					break;
				case 'a':
					if(i+1<argc)
						args = argv[i+1];
					i=i+1;
					break;
				case 'b':
					if(i+1<argc)
						path = argv[i+1];
					i=i+1;
					file = true;
					break;
				case 'o':
					overwrite = false;
					break;
				case 'r':
					useService = true;
					break;
				case 's':
					standalone = true;
					break;
				case 't':
					cleanTraces = true;
					break;
				default:
					help();
					return -1;
					break;
			}
		}
	}

	//need to know what to do, with wich user and what is the target
	if(computer == NULL ||
		(path == NULL && command == NULL) ||
		username == NULL)
	{
		help();
		return -1;
	}

	ptrstr = strstr(computer, "\\\\");
	//we need the "\\" characters in the computer name
	if(ptrstr == NULL)
	{
		help();
		return -1;
	}





//################################################################
//	INIT
//################################################################
	
	unmapShare(computer);

	//if no domain is specified with the username (no '\'), append the computer name
	if(strstr(username, "\\") == NULL)
	{
		len = strlen(ptrstr+2)+strlen(username)+2;
		fullUsername = (char*)malloc(sizeof(char)*(len));
		strcpy_s(fullUsername,len,ptrstr+2);
		strcat_s(fullUsername,len,"\\");
		strcat_s(fullUsername,len,username);
		username = fullUsername;
	}
	
	len = strlen(computer)+8;
	fullDriveName = (char*)malloc(sizeof(char) * (len));
	strcpy_s(fullDriveName,len,computer);
	strcat_s(fullDriveName,len,"\\admin$");

	//empty password = "", not NULL
	if(password == NULL)
	{
		password = (char*)malloc(1);
		password[0] = 0x00;
	}





//################################################################
//	START
//################################################################

	printf("\n\t\t== CONIX REMOTE EXECUTION TOOL v1.2 (2013) ==\n\n"
		"[-] Starting remote execution on %s with %s credentials\n",computer, username);

	if(!standalone)
	{
		printf("[-] Mapping the %s network drive... ", fullDriveName);

		returnValue = mapShare(username,password,fullDriveName);
		if(returnValue != 0)
		{
			printf("fail, aborting...\n");
			return -1;
		}

		printf("OK.\n[-] Copying %s service...\n",SERVICENAME);
		if(write_resource(fullDriveName, computer)== -1)
		{
			printf("[!] An error occured, aborting...\n");
			unmapShare(fullDriveName);
			return -1;
		}
		
		printf("[-] %s service copied successfuly!\n",SERVICENAME);

		if(path != NULL)
		{
			printf("[-] Copying %s... ",path);

			fileName = copyFileToRemoteShareAndGetFileName(path, fullDriveName,overwrite);
			if(fileName == NULL)
			{
				printf("[!] An error occured, aborting...\n");
				unmapShare(fullDriveName);
				free(fileName);
				return -1;
			}

			//modify the command
			len = strlen(fullDriveName)+1+strlen(fileName)+1;
			command = (char*)malloc(sizeof(char)*(len));
			strcpy_s(command,len,fullDriveName);
			strcat_s(command,len,"\\");
			strcat_s(command,len,fileName);
			free(fileName);
			printf("OK.\n");
		}

		if(!useService)
		{
			printf("[-] Starting %s using WMI:\n",SERVICENAME);
			returnValue = startWMICommand(EXECNAME,computer,username,password);
			if(returnValue != 0)
			{
				printf("[!] An error occured, aborting...\n");
				unmapShare(fullDriveName);
				return -1;
			}
		}
		else
		{
			printf("[-] Starting %s using Service Manager:\n",path);
			servname = (char*)malloc(sizeof(char)*servnameLen);
			strcpy_s(servname,servnameLen,"%SystemRoot%\\");
			strcat_s(servname,servnameLen,EXECNAME);
			strcat_s(servname,servnameLen," --service");
			returnValue = startRemoteService(servname,computer);
			free(servname);
			if(returnValue != 0)
			{
				printf("[!] An error occured, aborting...\n");
				unmapShare(fullDriveName);
				return -1;
			}
		}
		
		Sleep(1000);
		printf("[-] Service started successfuly.\n");

		//start dynamic communication
		dynamic(username,password,computer,command,args,file);

		// end
		if(useService)
		{
			printf("[-] Uninstalling service:\n");
			if(uninstallRemoteService(computer)==-1)
			{
				printf("[!] Warning: impossible to uninstall the service.\n");
				unmapShare(fullDriveName);
				return -1;
			}
		}

		unmapShare(fullDriveName);
	}
	else
	{
		if(path == NULL)
		{
			printf("[-] Running command \"%s\" using WMI:\n",command);
			returnValue = startWMICommand(command,computer,username,password);
			if(returnValue != 0)
			{
				printf("[!] An error occured, aborting...\n");
				unmapShare(fullDriveName);
				return -1;
			}
			printf("[-] Command executed.\n");
		}
		else
		{
			fileName = copyFileToRemoteShareAndGetFileName(path, fullDriveName,overwrite);
			if(fileName == NULL)
			{
				printf("[!] An error occured, aborting...\n");
				unmapShare(fullDriveName);
				free(fileName);
				return -1;
			}

			if(args != NULL)
			{
				len = strlen(fileName)+strlen(args)+2;
				command = (char*)malloc(sizeof(char)*(len));
				strcpy_s(command,len,fileName);
				strcat_s(command,len," ");
				strcat_s(command,len,args);
			}
			else
				command = fileName;

			free(fileName);
			printf("OK.\n[-] Running %s... ", path);
			returnValue = startWMICommand(command,computer,username,password);
			if(returnValue != 0)
			{
				printf("fail, aborting...\n");
				free(command);
				return -1;
			}
			printf("OK.\n");
			free(command);
		}
	}

	return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Displays help.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void help()
{
	printf(		   "\n CRET v1.2 (2013)\n"
		"\n Options \n"
		"\n"
			"\tSyntax: CRET.exe [options] where options are :\n"
			"\t-c \\\\COMPUTER : computer (IP address or hostname)\n"
			"\t-u [DOMAIN\\]USERNAME : username\n"
			"\t-p PASSWORD : password\n"
			"\t-b PATH : local binary file which will be copied on the remote machine\n"
			"\t-o : overwrite existing file\n"
			"\t-r : use remote service to start the interactivity instead of WMI\n"
			"\t-a \"ARGS\" : arguments to be given to the command\n"
			"\t-x \"COMMAND\" : run COMMAND with arguments if any\n"
			"\t-s : \"standalone\" command which does not requires interactivity\n"
			"\t     The CRET service will not be copied/used.\n"
			"\t-t : clean known traces on the system (prefetchs, registry keys, etc.)\n"
			"\t-h : display this help\n"
		"\n"
			"\tNB: you must have administrators rights on the computer to copy files.\n"
		"\n Examples\n"
		"\n"
		"CRET.exe -c \\\\mylaptop -u Domain\\Administrator -p pwd -x cmd\n"
		"> will launch an interactive cmd shell\n\n"
		"CRET.exe -c \\\\mylaptop -u Domain\\Administrator -p pwd -x cmd -r\n"
		"> will launch an interactive cmd shell using the \"PsExec\" method (remote service)\n\n"
		"CRET.exe -c \\\\mylaptop -u Administrator -p pwd -x \"netstat -an\"\n"
		"> will launch an interactive \"cmd /c netstat -an\" command\n\n"
		"CRET.exe -c \\\\mylaptop -u Administrator -p pwd -x \"cmd /c netstat > C:\\ret\" -s\n"
		"> will launch a \"cmd /c netstat > C:\\ret\" command without interactivity\n\n"
		"CRET.exe -c \\\\mylaptop -u Administrator -p pwd -b \"C:\\test.exe\" -a \"-b\"\n"
		"> will copy and execute interactively the local C:\\test.exe file, with \"-b\" arg\n\n"
		"CRET.exe -c \\\\mylaptop -u Administrator -p pwd -b \"C:\\test.exe\" -s\n"
		"> will copy and execute the local C:\\test.exe file, and nothing else.\n\n"
		"CRET.exe -c \\\\mylaptop -u Administrator -p pwd -b \"C:\\test.exe\" -r -t\n"
		"> will copy and execute interactively the local C:\\test.exe file, overwriting the existing one, and clean traces.\n"
		"\n"
		"\n Copyright 2013 Conix Security, Adrien Chevalier\n");
}
