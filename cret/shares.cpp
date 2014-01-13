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
//		Copy path to remoteShare, overwrite if flag set and returns the new filename.
//		NB : the returned char* size is MAX_PATH*sizeof(char) and must be free by the caller.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
char* copyFileToRemoteShareAndGetFileName(char* path, char* remoteShare, bool overwrite)
{
	char *pathName, *fileName, *driveName, *extName, *originalCurrentDirectory;

	//we just have to copy and generate the command
	if(strlen(path)>MAX_PATH)
	{
		printf("\t[!] Error : too long path.\n");
		return NULL;
	}
	originalCurrentDirectory = (char*)malloc(MAX_PATH *sizeof(char));

	if(GetCurrentDirectoryA(MAX_PATH,originalCurrentDirectory)==0)
	{
		free(originalCurrentDirectory);
		return NULL;
	}
	if(!SetCurrentDirectoryA(remoteShare))
	{
		free(originalCurrentDirectory);
		return NULL;
	}

	//get the file name
	// MAX_PATH > _MAX_DRIVE, _MAX_DIR, etc.
	pathName = (char*)malloc(MAX_PATH*sizeof(char));
	fileName = (char*)malloc(MAX_PATH*sizeof(char));
	driveName = (char*)malloc(MAX_PATH*sizeof(char));
	extName = (char*)malloc(_MAX_EXT *sizeof(char));

	_splitpath_s(path,driveName,MAX_PATH,pathName,MAX_PATH,fileName,MAX_PATH,extName,_MAX_EXT);
	free(pathName);
	free(driveName);

	if(strlen(fileName)+strlen(extName) > MAX_PATH-1)
	{
		free(fileName);
		free(extName);
		printf("\t[!] Error : too long path.\n");
		SetCurrentDirectoryA(originalCurrentDirectory);
		free(originalCurrentDirectory);
		return NULL;
	}

	strcat_s(fileName,MAX_PATH,extName);
	free(extName);

	//now copy the file
	if(CopyFileA(path,fileName,overwrite)==0)
	{
		printf("\t[!] Error : cannot copy the file.\n");
		free(fileName);
		SetCurrentDirectoryA(originalCurrentDirectory);
		free(originalCurrentDirectory);
		return NULL;
	}

	SetCurrentDirectoryA(originalCurrentDirectory);
	free(originalCurrentDirectory);
	return fileName;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Maps the "target" remote share with "username" credentials.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD mapShare(char* username, char* password, char* target)
{
	
	NETRESOURCEA netResource;
	DWORD returnValue = 0;
	memset(&netResource, 0x00, sizeof(NETRESOURCEA));
	netResource.dwType = RESOURCETYPE_DISK;
	netResource.lpLocalName = NULL;
	netResource.lpProvider = NULL;
	netResource.lpRemoteName = target;


	returnValue = WNetAddConnection2A(&netResource,password,username,CONNECT_TEMPORARY);
	if(returnValue==0)
	{
		SetCurrentDirectoryA("C:\\");
		WNetCancelConnectionA(target, FALSE);
		returnValue = WNetAddConnection2A(&netResource,password,username,CONNECT_TEMPORARY);
	}

	return returnValue;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unmap a remote share.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void unmapShare(char* target)
{
	DWORD returnValue;

	//change to local drive
	SetCurrentDirectoryA("C:\\");
	returnValue = WNetCancelConnectionA(target, FALSE);
}
