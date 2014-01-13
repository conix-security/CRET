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
//		Uninstalls (after stopping) the remote service.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD uninstallRemoteService(char* target)
{
	SC_HANDLE hSCM;
	SC_HANDLE hService;
	SERVICE_STATUS status;
	char* striptarget=target;

	if(target[0]=='\\' && target[1]=='\\')
		striptarget=striptarget+2;

	hSCM=OpenSCManagerA(striptarget, 0, SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
		return -1;

	hService=OpenServiceA(hSCM,SERVICENAME,SERVICE_ALL_ACCESS);
	if(hService == NULL)
	{
		CloseServiceHandle(hSCM);
		printf("\t[-] Service is not installed.\n");
		return 0;
	}
	if(!QueryServiceStatus(hService,&status))
	{
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCM);
		return 0;
	}

	if(status.dwCurrentState == SERVICE_START_PENDING || status.dwCurrentState == SERVICE_STOP_PENDING || status.dwCurrentState == SERVICE_PAUSE_PENDING)
		printf("\t[-] An operation is pending, waiting for its completion...\n");

	while(status.dwCurrentState == SERVICE_START_PENDING || status.dwCurrentState == SERVICE_STOP_PENDING || status.dwCurrentState == SERVICE_PAUSE_PENDING)
	{
		Sleep(1000);
		if(!QueryServiceStatus(hService,&status))
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCM);
			return 0;
		}
	}

	if(status.dwCurrentState == SERVICE_RUNNING)
	{
		printf("\t[-] Stopping service...");
		if(!ControlService(hService,SERVICE_CONTROL_STOP,&status))
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCM);
			printf(" fail.\n");
			return -1;
		}
		printf(" OK.\n");
	}
	else
		printf("\t[-] Service already stopped.\n");

	printf("\t[-] Uninstalling service... ");
	if(!DeleteService(hService))
	{
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCM);
		printf("fail.\n");
		return -1;
	}
	printf("OK.\n");

	return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs and starts remote service on "target".
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD startRemoteService(char* path, char* target)
{
	SC_HANDLE hSCM;
	SC_HANDLE hService;
	char choice;
	SERVICE_STATUS status;
	char* striptarget=target;

	if(target[0]=='\\' && target[1]=='\\')
		striptarget=striptarget+2;

	hSCM=OpenSCManagerA(striptarget, 0, SC_MANAGER_ALL_ACCESS);
	if(hSCM == NULL)
		return -1;

	hService=OpenServiceA(hSCM,SERVICENAME,SERVICE_ALL_ACCESS);
	if(hService == NULL)
	{
		printf("\t[-] Installing service... ");
		
		hService = CreateServiceA(hSCM,SERVICENAME,"Conix Remote Execution Tool Service",SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
		if(hService == NULL)
		{
			hService=OpenServiceA(hSCM,SERVICENAME,SERVICE_ALL_ACCESS);
			if(hService == NULL)
			{
				CloseServiceHandle(hSCM);
				CloseServiceHandle(hService);
				uninstallRemoteService(target);
				printf("fail.\n");
				return -1;
			}
		}
		printf("OK.\n"
			"\t[-] Starting service... ");
		
		if(StartServiceA(hService,NULL,NULL)==FALSE)
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCM);
			printf("fail, removing service.\n");
			uninstallRemoteService(target);
			return -1;
		}
		printf("OK.\n\t[-] Waiting... ");

		for(int i=0; i<5; i++)
		{
			if(QueryServiceStatus(hService,&status))
			{
				if(status.dwCurrentState == SERVICE_RUNNING)
				{
					CloseServiceHandle(hService);
					CloseServiceHandle(hSCM);
					printf(" OK, service is running.\n");
					return 0;
				}
				else if(status.dwCurrentState == SERVICE_START_PENDING)
					i--;
			}
			Sleep(1000);
		}
		printf(" fail, removing service.\n");
		uninstallRemoteService(target);
		CloseServiceHandle(hService);
	}
	else
	{
		printf("\t[!] Warning: an existing %s service has been found.\n"
			"\t[!] Do you want to stop/uninstall the existing %s service? (Y/N): \n",SERVICENAME,SERVICENAME);
		choice = 'A';
		while(choice != 'Y' && choice != 'N')
			choice = getchar();

		if(choice == 'Y')
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCM);
			printf("\t[-] Uninstalling service...\n");
			uninstallRemoteService(target);
			
			Sleep(1000);
			return startRemoteService(path,target);
		}
		else
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCM);
			return -1;
		}
	}

	CloseServiceHandle(hSCM);
	return -1;

}
