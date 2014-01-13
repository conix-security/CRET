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
//		Extract the service resource onto \\computer\admin$
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD write_resource(char* path, char* computer)
{
	HRSRC serviceRsc = NULL;
	HGLOBAL serviceHandle = NULL;
	HANDLE serviceFileHandle = NULL;
	DWORD serviceSize = 0;
	char choice;
	DWORD returnValue;

	//service extraction
	serviceRsc = FindResourceA(NULL, "CRETSVC", "PEFILE");
	if(serviceRsc == NULL)
	{
		printf("\t[!] Error: impossible to load the service resource, aborting...\n");
		return -1;
	}
	serviceHandle = LoadResource(NULL, serviceRsc);
	if(serviceHandle == NULL)
	{
		printf("\t[!] Error: impossible to load the service resource, aborting...\n");
		return -1;
	}
	serviceSize = SizeofResource(NULL, serviceRsc);
	if(serviceSize == 0)
	{
		printf("\t[!] Error: impossible to load the service resource, aborting...\n");
		return -1;
	}

	//copying the ressource to the network share

	if(!SetCurrentDirectoryA(path))
	{
		printf("\t[!] Error: impossible to copy the service, aborting...\n");
		return -1;
	}
	serviceFileHandle = CreateFileA(EXECNAME, GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if(serviceFileHandle == INVALID_HANDLE_VALUE)
	{
		returnValue = GetLastError();
		if(returnValue == ERROR_ALREADY_EXISTS || returnValue == ERROR_FILE_EXISTS)
		{
			printf("\t[!] Warning: do you want to overwrite the existing %s file? (Y/N) :",EXECNAME);
			choice='A';
			while(choice!='Y' && choice!='N')
				choice = getchar();
			//overwriting
			if(choice == 'Y')
				serviceFileHandle = CreateFileA(EXECNAME, GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		}
		
		if(serviceFileHandle == INVALID_HANDLE_VALUE)
		{
			printf("\t[!] Error: impossible to copy the service.\n"
				"\t[-] A running %s service may block the file. Do you want to try uninstalling it? (Y/N) :",SERVICENAME);

			choice='A';
			while(choice!='Y' && choice!='N')
				choice=getchar();

			if(choice=='Y')
			{
				printf("\t[-] Uninstalling %s...\n",SERVICENAME);
				if(uninstallRemoteService(computer)==0)
				{
					Sleep(1000);
					serviceFileHandle = CreateFileA(EXECNAME, GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if(serviceFileHandle == INVALID_HANDLE_VALUE)
						return -1;
				}
				else
					return -1;
			}
			else
				return -1;
			choice = 'A';
		}
	}
	if(!WriteFile(serviceFileHandle, (PVOID)serviceHandle, serviceSize, &returnValue, NULL))
	{
		printf("\t[!] Error: could not copy the file, aborting...\n");
		CloseHandle(serviceFileHandle);
		return -1;
	}
	CloseHandle(serviceFileHandle);

	return 0;

}
