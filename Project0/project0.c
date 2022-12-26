/*
	File: project1.c

*/

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <windows.h>

void* SyscallBaseFinder_(unsigned long long ReturnedDllBase, char* NtApiName, size_t LenNtApiName);
unsigned long long DllModuleBaseFinder_(char* ModuleName, size_t LenModuleName);

unsigned int SyscallIdFinder(char* ApiBase){

	return (unsigned int)*(ApiBase+4);
}

int main(int argc, char** argv){
	
	/*Retrieve the base address of module ntdll using TEB */
	wchar_t* ModuleNameToFind = L"ntdll.dll";	
	unsigned long long ReturnedDllBase;
	size_t LenModuleName = wcslen(ModuleNameToFind);   						  //sizeof(ModuleNameToFind)/sizeof(wchar_t);
	
	ReturnedDllBase = DllModuleBaseFinder_(ModuleNameToFind, 
						LenModuleName
						);	
	printf("ntdll.dll Base: %p\n",ReturnedDllBase);												
																									
	/*Find the base address of the NtApi*/
	char* NtApiName = "NtAllocateVirtualMemory";
	size_t LenNtApiName = strlen(NtApiName);
	void* ReturnedApiBase;
	ReturnedApiBase = SyscallBaseFinder_(ReturnedDllBase, 									// retrieve API address
						NtApiName,
						LenNtApiName
						);
						
	printf("NtAllocateVirtualMemory Base: %p\n", ReturnedApiBase);
	
	/*Find SyscallID*/
	unsigned int SyscallId;
	SyscallId = SyscallIdFinder(ReturnedApiBase);
	printf("NtAllocateVirtualMemory Syscall Id: %i\n", SyscallId);

	getch();

	
	return EXIT_SUCCESS;
}
