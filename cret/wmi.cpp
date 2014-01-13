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
//		Sends WMI command to target after logging on.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD startWMICommand(char* command, char* target, char* username, char* password)
{	
	HRESULT hres;
	IWbemLocator *pLoc = NULL;
	IWbemServices *pSvc = NULL;
	COAUTHIDENTITY *userAcct =  NULL ;
	COAUTHIDENTITY authIdent;
	char* serverWMIA;
	PWCHAR serverWMIW;
	PWCHAR usernameW;
	PWCHAR commandW;
	PWCHAR passwordW;
	WCHAR pszDomain[CREDUI_MAX_USERNAME_LENGTH+1];
	WCHAR pszUserName[CREDUI_MAX_USERNAME_LENGTH+1];
	PWCHAR slash;
	int len = 0;

	// WCHAR
	len = strlen(target)+12;
	serverWMIA = (char*)malloc(sizeof(char)*(len));
	strcpy_s(serverWMIA, len, target);
	strcat_s(serverWMIA, len, "\\ROOT\\CIMV2");
	len = MultiByteToWideChar(CP_ACP,0,serverWMIA,-1,NULL,0);
	serverWMIW = (PWCHAR)malloc(sizeof(WCHAR)*len);
	MultiByteToWideChar(CP_ACP,0,serverWMIA,-1,serverWMIW,len);
	free(serverWMIA);
	len = MultiByteToWideChar(CP_ACP,0,username,-1,NULL,0);
	usernameW = (PWCHAR)malloc(sizeof(WCHAR)*len);
	MultiByteToWideChar(CP_ACP,0,username,-1,usernameW,len);
	len = MultiByteToWideChar(CP_ACP,0,password,-1,NULL,0);
	passwordW = (PWCHAR)malloc(sizeof(WCHAR)*len);
	MultiByteToWideChar(CP_ACP,0,password,-1,passwordW,len);
	len = MultiByteToWideChar(CP_ACP,0,command,-1,NULL,0);
	commandW = (PWCHAR)malloc(sizeof(WCHAR)*len);
	MultiByteToWideChar(CP_ACP,0,command,-1,commandW,len);

	hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
	if(hres<0)
	{
		free(usernameW);
		free(passwordW);
		free(commandW);
		free(serverWMIA);
		free(serverWMIW);
		return -1;
	}
	hres =  CoInitializeSecurity(NULL,-1,NULL,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IDENTIFY,NULL,EOAC_NONE,NULL);	   
	if(hres<0)
	{
		free(usernameW);
		free(passwordW);
		free(commandW);
		free(serverWMIA);
		free(serverWMIW);
		CoUninitialize();
		return -1;
	}
	hres = CoCreateInstance(CLSID_WbemLocator,0,CLSCTX_INPROC_SERVER,IID_IWbemLocator, (LPVOID *) &pLoc);
	if(hres<0)
	{
		free(usernameW);
		free(passwordW);
		free(commandW);
		free(serverWMIA);
		free(serverWMIW);
		CoUninitialize();
		return -1;
	}

	//WMI connection
	hres = pLoc->ConnectServer(_bstr_t(serverWMIW),_bstr_t(usernameW),_bstr_t(passwordW),NULL,NULL,NULL,NULL,&pSvc);
	if(hres<0)
	{
		free(usernameW);
		free(passwordW);
		free(commandW);
		free(serverWMIA);
		free(serverWMIW);
		pLoc->Release();	 
		CoUninitialize();
		return -1;
	}

	//Set ProxyBlanket options
	memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
	authIdent.PasswordLength = wcslen (passwordW);
	authIdent.Password = (USHORT*)passwordW;
	slash = wcschr (usernameW, L'\\');
	if(slash == NULL)
	{
		free(usernameW);
		free(passwordW);
		free(commandW);
		free(serverWMIA);
		free(serverWMIW);
		pSvc->Release();
		pLoc->Release();	 
		CoUninitialize();
		return -1;
	}
	wcscpy_s(pszUserName,CREDUI_MAX_USERNAME_LENGTH+1, slash+1);
	authIdent.User = (USHORT*)pszUserName;
	authIdent.UserLength = wcslen(pszUserName);
	wcsncpy_s(pszDomain, CREDUI_MAX_USERNAME_LENGTH+1, usernameW, slash - usernameW);
	authIdent.Domain = (USHORT*)pszDomain;
	authIdent.DomainLength = slash - usernameW;
	authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
	userAcct = &authIdent;
	
	//Set the ProxyBlanket
	hres = CoSetProxyBlanket(pSvc,RPC_C_AUTHN_DEFAULT,RPC_C_AUTHZ_DEFAULT,COLE_DEFAULT_PRINCIPAL,RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_IMP_LEVEL_IMPERSONATE,userAcct,EOAC_NONE);
	if(hres<0)
	{
		free(usernameW);
		free(passwordW);
		free(commandW);
		free(serverWMIA);
		free(serverWMIW);
		pSvc->Release();
		pLoc->Release();	 
		CoUninitialize();
		return -1;
	}


	BSTR MethodName = SysAllocString(L"Create");
	BSTR ClassName = SysAllocString(L"Win32_Process");

	IWbemClassObject* pClass = NULL;
	hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);
	IWbemClassObject* pInParamsDefinition = NULL;
	hres = pClass->GetMethod(MethodName, 0, 
		&pInParamsDefinition, NULL);
	IWbemClassObject* pClassInstance = NULL;
	hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

	// Create the values for the "in" parameters
	VARIANT varCommand;
	varCommand.vt = VT_BSTR;
	varCommand.bstrVal = BSTR(commandW);

	// Store the value for the "in" parameters
	hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

	 // Execute Method
	IWbemClassObject* pOutParams = NULL;
	hres = pSvc->ExecMethod(ClassName, MethodName, 0,
	NULL, pClassInstance, &pOutParams, NULL);

	if (FAILED(hres))
	{
		free(usernameW);
		free(passwordW);
		free(commandW);
		free(serverWMIA);
		free(serverWMIW);
		VariantClear(&varCommand);
		SysFreeString(ClassName);
		SysFreeString(MethodName);
		pClass->Release();
		pInParamsDefinition->Release();
		pOutParams->Release();
		pSvc->Release();
		pLoc->Release();	 
		CoUninitialize();
		return -1;
	}


	free(usernameW);
	free(passwordW);
	free(commandW);
	free(serverWMIA);
	free(serverWMIW);
	SecureZeroMemory(pszUserName, sizeof(pszUserName));
	SecureZeroMemory(pszDomain, sizeof(pszDomain));
	VariantClear(&varCommand);
	SysFreeString(ClassName);
	SysFreeString(MethodName);
	pClass->Release();
	pInParamsDefinition->Release();
	pOutParams->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return 0;
}
