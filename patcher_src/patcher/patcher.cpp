// patcher.cpp : Defines the entry point for the console application.
//
#define _DEBUG 

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <string>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

typedef LONG(NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI *NtResumeProcess)(IN HANDLE ProcessHandle);

/*function prototypes*/
bool isSelfEX(char* passarg);
int injectHook(DWORD pid);
void suspendProcess(DWORD pid, bool state);
char* getAddressOfData(DWORD pid, const char *data, size_t len);
char* opCodeLSB(char* VA, const int opCode);

/*globals*/
uintptr_t genPassHash_Opcode;
uintptr_t genPassHashProc_VA;
uintptr_t abortInit_VA;

PROCESS_INFORMATION procInfoS1 = { 0 };
PROCESS_INFORMATION procInfoS2 = { 0 };

// Assembly x86 instructions: sparksandflames.com/files/x86InstructionChart.html

/*
Note to self:
The Setup loader now extracts the Setup program executable file with a ".tmp" extension.
Versions 5.2.0 and 5.2.1 used a ".exe.tmp" extension, which reportedly, in some cases,
caused an "Unable to execute file in temporary directory" error message on systems
with a certain antivirus program installed. We were unable to reproduce the error in our own tests,
however; it is suspected that this may have only impacted users with custom filename blocking rules
defined in their antivirus configuration.
*/

int main(int argc, char** argv)
{
	for (int i = 0; i < argc; ++i)
		cout << argv[i] << "\n";
	/*
	argv[0] = C:\Users\ADMINI~1\AppData\Local\Temp\is-TC3QP.tmp\target.tmp
	argv[1] = /SL5=$7706F6,24043531,76288,C:\Users\Administrator\Documents\somefolder\target.exe
	*/

	/* checking if arguments are valid before we continue */
	if (argv[1] != NULL && !isSelfEX(argv[0])) //do we have two args
	{
		SetConsoleTitle(".:: Inno ROPS runtime encryption password extractor v1.0 ::.");
		system("Color 2");
		char *childexec = strrchr(argv[0], '.');   //argv 1 dbg ca, 0 rel
		string sL5 = argv[1];					  //argv 2 dbg ca, 1 rel
		string lpCommandLine = sL5.c_str();
		if (sL5.length() > 6 && sL5.length() <= 260) {
			sL5 = sL5.substr(0, 5);
			lpCommandLine.insert(5, 1, char(0x22));						// /SL5="
			lpCommandLine.push_back(char(0x22));						// " to end of /SL5= string
			lpCommandLine.insert(0, argv[0]);							// insert childexec process executable path
			lpCommandLine.insert(strlen(argv[0]), 1, char(0x22));		// " to pos 0 childexec
			lpCommandLine.insert(strlen(argv[0]) + 1, 1, char(0x20));		// space between " /SL5=
			lpCommandLine.insert(0, 1, char(0x22));						// add " to begin of childexec executable path
			unsigned sz = lpCommandLine.length();
			char str[8] = { 0x20,0x2F,0x53,0x49,0x4C,0x45,0x4E,0x54 };	// append /SILENT switch
			for (int i = 0; i < sizeof(str); ++i)
				lpCommandLine.insert(sz + i, 1, str[i]);				//lpComandLine.resize(sz+i, str[i]);
		}
		if (strcmp(childexec, ".tmp") == 0 && strcmp(sL5.c_str(), "/SL5=") == 0) // verify arguments
		{
			printf("[+] Arguments passed correctly.\n");
			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			if (CreateProcess(NULL, (LPSTR)lpCommandLine.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &procInfoS2))
			{
				printf("[+] CreateProcess detoured successfully.\n");
				printf("[+] Suspending process.\n");
				//Sleep(100); /* not required, but might be fun to show a glicthed installer on the screen */
				injectHook(procInfoS2.dwProcessId);
				suspendProcess(procInfoS2.dwProcessId, true);		
				/*
				Memory Map: section .CODE
				Address=0048297F
				Disassembly=mov eax,tempy.483A98
				String="Setup version: Inno Setup version 5.6.1 (a)"
				sizeof(String) = 43
				search for "Setup version: Inno Setup version "
				add 9 chars "5.6.1 (a)"
				check memory address 0x00400000
				*/
				char patVersion[] = {
					0x53, 0x65, 0x74, 0x75, 0x70, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,0x6f,
					0x6e, 0x3a, 0x20, 0x49, 0x6e, 0x6e, 0x6f, 0x20, 0x53, 0x65,0x74,0x75,
					0x70, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20
				}; 
				char *VA = getAddressOfData(procInfoS2.dwProcessId, patVersion, sizeof(patVersion));
				if (VA)
				{
					char* vBuf[43];
					SIZE_T nSize = 43;
					printf("[+] Pattern version found: .CODE VA: 0x%08x", (uintptr_t)VA);
					printf("\n");
					if (ReadProcessMemory(procInfoS2.hProcess, (LPVOID)VA, &vBuf, strlen(patVersion) + 9, &nSize))
					{
						int loc = 0;
						char* vpBuf = (char*)vBuf;
						char* innoCharset = strrchr((CHAR*)(vpBuf), 0x20);
						string innoVer;
						string icsF = (char*)innoCharset;
						icsF = icsF.erase(0, 1);
						innoCharset = (char*)icsF.c_str();
						if (strcmp(innoCharset, "(a)") == 0) /*get chatset enum, unicode will not work! */
						{
							printf("[+] Inno setup CharSet: (a) Ansi\n");
						}
						else
						{
							printf("[+] Inno setup CharSet: (u) Unicode\n");
						}
						for (int i = 34; i < 39; ++i, ++loc) /* snack my version */
						{
							innoVer.insert(loc, 1, (CHAR)(vpBuf[i]));
						}
						printf("[+] Inno Version: %s\n", innoVer.c_str());
						//"PasswordCheckHash" PasswordCheckHash 
						// find procedure GeneratePasswordHashAndSalt
						char patPasswordCheckHashStr[] = {
							0x50, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x43,
							0x68, 0x65, 0x63, 0x6B, 0x48, 0x61, 0x73, 0x68
						};
						char *VA = getAddressOfData(procInfoS2.dwProcessId, patPasswordCheckHashStr, sizeof(patPasswordCheckHashStr));
						if (VA)
						{
							printf("[+] Pattern PasswordCheckHash found: .CODE VA: 0x%08x", (uintptr_t)VA);
							printf("\n");
							char *patGeneratePasswordHashProcedure;
							patGeneratePasswordHashProcedure = opCodeLSB((char*)VA, 186); /* MOV eDX Iv, BA = 186 */
							char *VA = getAddressOfData(procInfoS2.dwProcessId, patGeneratePasswordHashProcedure, sizeof(patGeneratePasswordHashProcedure));
							free(patGeneratePasswordHashProcedure);
							if (VA)
							{
								genPassHashProc_VA = (uintptr_t)VA;
								printf("[+] Pattern Procedure GeneratePasswordHash found: .CODE VA: 0x%08x", (uintptr_t)VA);
								printf("\n");
								/*
								search string to find func "AbortInit"
								Address=00451DB4
								Disassembly = mov ecx, target.451F34 String = "Messages file \"%s\" is missing. Please correct the problem or obtain a new copy of the program."
								TSetupMessageID msgSetupFileCorruptOrWrongVer
								jump to pop ebx with MessageBoxA/W and Abort setup :)
								*/
								char patAbortInit[] = {
									0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x20, 0x66, 0x69, 0x6C, 0x65, 0x20, 0x22, 0x25,
									0x73, 0x22, 0x20, 0x69, 0x73, 0x20, 0x6D, 0x69, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x2E, 0x20, 0x50,
									0x6C, 0x65, 0x61, 0x73, 0x65, 0x20, 0x63, 0x6F, 0x72, 0x72, 0x65, 0x63, 0x74, 0x20, 0x74, 0x68,
									0x65, 0x20, 0x70, 0x72, 0x6F, 0x62, 0x6C, 0x65, 0x6D, 0x20, 0x6F, 0x72, 0x20, 0x6F, 0x62, 0x74,
									0x61, 0x69, 0x6E, 0x20, 0x61, 0x20, 0x6E, 0x65, 0x77, 0x20, 0x63, 0x6F, 0x70, 0x79, 0x20, 0x6F,
									0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x2E
								};
								char *VA = getAddressOfData(procInfoS2.dwProcessId, patAbortInit, sizeof(patAbortInit));
								if (VA)
								{
									printf("[+] Pattern String in AbortInit found: .CODE VA: 0x%08x", (uintptr_t)VA);
									printf("\n");
									char *patAbortInit;
									patAbortInit = opCodeLSB((char*)VA, 185); /* MOV eCX Iv, B9 = 185 */
									char *VA = getAddressOfData(procInfoS2.dwProcessId, patAbortInit, sizeof(patAbortInit));
									free(patAbortInit);
									if (VA)
									{
										VA = VA - 0x0D; /* minus 13 bytes*/
										abortInit_VA = (uintptr_t)VA;
										printf("[+] Pattern Procedure AbortInit found: .CODE VA: 0x%08x", (uintptr_t)VA);
										printf("\n");

										(uintptr_t)genPassHash_Opcode = (uintptr_t)abortInit_VA - (uintptr_t)genPassHashProc_VA - 5;

										std::ostringstream ss;										
										ss << std::uppercase << std::hex << 0xE9 << (((uintptr_t)genPassHash_Opcode >> 24) | (((uintptr_t)genPassHash_Opcode << 8) & 0x00FF0000) |
											(((uintptr_t)genPassHash_Opcode >> 8) & 0x0000FF00) | ((uintptr_t)genPassHash_Opcode << 24));
										std::string result = ss.str();

										char opCodeJMPAbortInit[5];
										for (size_t i = 0; i < result.length(); i += 2)
										{
											opCodeJMPAbortInit[i / 2] = std::stoi(result.substr(i, 2), nullptr, 16);
											ss << ((i < 1) ? " { 0x" : ", 0x") << hex << (unsigned)static_cast <unsigned char>(opCodeJMPAbortInit[i / 2]) << ((i == result.length() - 2) ? " }" : "");
										}
										std::string hexSearch = ss.str();
										char buf[sizeof(ss)]; sprintf_s(buf, "[+] Array: %s", hexSearch.c_str());
										cout << string(buf) <<  endl;

										if (WriteProcessMemory(procInfoS2.hProcess, (LPVOID*)genPassHashProc_VA, opCodeJMPAbortInit, sizeof(opCodeJMPAbortInit), (SIZE_T*)(opCodeJMPAbortInit)))
										{
											printf("[+] JMP injected in Procedure GeneratePasswordHash to InitAbort.\n");
											printf("[+] NtResumeProcess -> Trigger detour hook ..\n");
											suspendProcess(procInfoS2.dwProcessId, false); /* .:: trigger time >=') */

											HANDLE hPipe;
											char buffer[1024];
											DWORD dwRead;
											hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\ispwdmp"),
												PIPE_ACCESS_DUPLEX,
												PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
												1,
												1024 * 16,
												1024 * 16,
												NMPWAIT_USE_DEFAULT_WAIT,
												NULL);
											while (hPipe != INVALID_HANDLE_VALUE)
											{
												if (ConnectNamedPipe(hPipe, NULL) != FALSE)
												{
													while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
													{
														buffer[dwRead] = '\0';
														printf("[+] ============================================================== [+]\n");
														printf("[+] Encryption password: %s\n", buffer);
														printf("[+] ============================================================== [+]\n");
														system("pause");
														return 0;
													}
												}
												DisconnectNamedPipe(hPipe);
											}
											system("pause");
											return 0;
										}
										else
										{
											printf("[-] Error Injecting instructions in Procedure GeneratePasswordHash\n");
										}
									}
									else
									{
										printf("[-] Error pattern Procedure AbortInit not found.\n");
									}
								}
								else
								{
									printf("[-] Error pattern string AbortInit not found.\n");
								}
							}
							else
							{
								printf("[-] Error Procedure GeneratePasswordHash pattern not found.\n");
							}
						}
						else
						{
							printf("[-] Error PasswordCheckHash pattern not found.\n");
						}
					}
					else
					{
						printf("[-] Error while reading version from memory.\n");
					}
				}
				else
				{
					printf("[-] Error version pattern not found.\n");
				}
				system("pause");
				return 0;
			}
			else
			{
				printf("[-] Failed to start the process.\n");
				system("pause");
			}
		}
		else
		{
			printf("[-] Arguments are incorrect\n");
			system("pause");
		}
	}
	else
	{
		SetConsoleTitle(".:: Inno main setup detour hook injector ::.");
		system("Color 4");
		printf("[+] Stage 1 staring main loader.\n");
		STARTUPINFO si = { sizeof(STARTUPINFO) };
		si.cb = sizeof(si);
		if (CreateProcess(argv[1], NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &procInfoS1))
		{
			DWORD pid = procInfoS1.dwProcessId;
			printf("[+] Main inno loader started.\n");
			injectHook(pid);
			system("pause");
			return 0;
		}
		else
		{
			printf("[-] Failed to start the main inno loader.\n");
			printf("[-] Dump argv: %s\n", argv[1]);
			system("pause");
		}
	}
}

char* opCodeLSB(char* VA, const int opCode)
{
	std::ostringstream ss; /* toupper << hex << inject desired opcode << LSB shift to right (litte endian) */
	ss << std::uppercase << std::hex << opCode << (((uintptr_t)VA >> 24) | (((uintptr_t)VA << 8) & 0x00FF0000) |
			(((uintptr_t)VA >> 8) & 0x0000FF00) | ((uintptr_t)VA << 24));
	std::string result = ss.str();
	char *buffer;
	buffer = (char*)malloc(strlen(ss.str().c_str()) / 2);
	#ifdef _DEBUG 
		printf("[+] SIZE OF SS = %i\n", result.length());
		printf("[+] SIZE OF MALLOC = %i\n", strlen(ss.str().c_str())/2);
	#endif
	for (size_t i = 0; i < result.length(); i += 2)
	{
		buffer[i / 2] = std::stoi(result.substr(i, 2), nullptr, 16);
		ss << ((i < 1) ? " { 0x" : ", 0x") << hex << (unsigned)static_cast <unsigned char>(buffer[i / 2]) << ((i == result.length() - 2) ? " }" : "");
	}
	std::string hexSearch = ss.str();
	char buf[sizeof(ss)]; sprintf_s(buf, "[+] Array: %s", hexSearch.c_str());
	cout << string(buf) << endl;

	return buffer;
}

bool isSelfEX(char* firstargv)
{
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	if (strcmp(firstargv, buffer) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void suspendProcess(DWORD pid, bool state)
{
	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandle((LPCTSTR)"ntdll"), "NtSuspendProcess");
	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandle((LPCTSTR)"ntdll"), "NtResumeProcess");

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (state)
	{
		pfnNtSuspendProcess(processHandle);
	}
	else
	{
		pfnNtResumeProcess(processHandle);
	}
	CloseHandle(processHandle);
}

int injectHook(DWORD pid)
{
	char buffer[MAX_PATH]; //get full hook dll path 
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::string dllpath = buffer;
	dllpath = dllpath.substr(0, dllpath.find_last_of("\\/")) + TEXT("\\minHook.dll");
	const char* dll = dllpath.c_str();

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); //Gets the process handle for the target process
	if (OpenProcess == NULL)
	{
		printf("[-] Could not find process\n");
	}

	HMODULE hModule = GetModuleHandle("kernel32.dll"); //Retrieves kernel32.dll module handle for getting loadlibrary base address
	LPVOID lpBaseAddress = (LPVOID)GetProcAddress(hModule, "LoadLibraryA"); //Gets address for LoadLibraryA in kernel32.dll
	if (lpBaseAddress == NULL)
	{
		printf("[-] Unable to locate LoadLibraryA\n");
		return -1;
	}

	LPVOID lpSpace = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //Allocates space inside for inject.dll to our target process
	if (lpSpace == NULL)
	{
		printf("\n[-] Could not allocate memory in process %u", pid);
		return -1;
	}

	int n = WriteProcessMemory(hProcess, lpSpace, dll, strlen(dll), NULL); //Write inject.dll to memory of process
	if (n == 0)
	{
		printf("[-] Could not write to process's address space\n");
		return -1;
	}
	HANDLE hThread;
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, NULL, NULL);
	if (hThread == NULL)
	{
		return -1;
	}
	else
	{
		DWORD threadId = GetThreadId(hThread);
		DWORD processId = GetProcessIdOfThread(hThread);
		printf("[+] Detour hook injected in thread id: %d for pid: %d\n", threadId, processId);
		CloseHandle(hProcess);
		return 0;
	}
}

char* getAddressOfData(DWORD pid, const char *data, size_t len)
{
	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (process)
	{
		SYSTEM_INFO si;
		GetSystemInfo(&si);

		MEMORY_BASIC_INFORMATION info;
		std::vector<char> chunk;
		char* p = 0;
		while (p < si.lpMaximumApplicationAddress)
		{
			if (VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info))
			{
				p = (char*)info.BaseAddress;
				chunk.resize(info.RegionSize);
				SIZE_T bytesRead;
				if (ReadProcessMemory(process, p, &chunk[0], info.RegionSize, &bytesRead))
				{
					for (size_t i = 0; i < (bytesRead - len); ++i)
					{
						if (memcmp(data, &chunk[i], len) == 0)
						{
							return (char*)p + i;
						}
					}
				}
				p += info.RegionSize;
			}
		}
	}
	return 0;
}