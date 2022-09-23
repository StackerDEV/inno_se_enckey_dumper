// minHook.cpp : Defines the entry point for the console application.
//
#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <string>


#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

using namespace std;
#include "MinHook.h"

//Typedef CP
typedef int (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef int (WINAPI *CREATEPROCESSW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
	BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

//Typedef MSB
typedef int (WINAPI *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);

// Pointer for calling original CreateProcessA/W.
CREATEPROCESSA fpCreateProcessA = NULL;
CREATEPROCESSW fpCreateProcessW = NULL;

// Pointer for calling original MessageBoxA/W.
MESSAGEBOXA fpMessageBoxA = NULL;
MESSAGEBOXW fpMessageBoxW = NULL;

char buffer[1024];
wchar_t w_buffer[1024];
int WINAPI DetourCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation) {


	char buffer[MAX_PATH]; //get directory of executable injected in 
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::string exep = buffer;
	exep = exep.substr(0, exep.find_last_of("\\/")) + TEXT("\\patcher.exe"); //add patcher.exe parser


	MH_DisableHook(&CreateProcessA); //release hook
	MH_DisableHook(&CreateProcessW);

	STARTUPINFO info = { sizeof(info) }; //run patcher.exe parser with argument for patching
	PROCESS_INFORMATION processInfo;
	if (CreateProcessA(exep.c_str(), (LPSTR)lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
	{
		WaitForSingleObject(processInfo.hProcess, INFINITE);
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}

	DWORD pid = GetCurrentProcessId(); //kill the main process InnoSetupLdr after unpacking to %temp%
	HANDLE hnd;
	hnd = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, pid);
	TerminateProcess(hnd, 0);

	return 0;
}
int WINAPI DetourCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation) {

	char buffer[MAX_PATH]; //get directory of executable injected in 
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::string exep = buffer;
	exep = exep.substr(0, exep.find_last_of("\\/")) + TEXT("\\patcher.exe"); //add patcher.exe parser

	MH_DisableHook(&CreateProcessA);
	MH_DisableHook(&CreateProcessW); //release hook

	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };

	std::wstring widestr = std::wstring(exep.begin(), exep.end());

	if (CreateProcessW((LPWSTR)widestr.c_str(), (LPWSTR)lpCommandLine, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi)) // arg 6,  0 : CREATE_UNICODE_ENVIRONMENT
	{
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	DWORD pid = GetCurrentProcessId(); //kill the main process InnoSetupLdr after unpacking to %temp%
	HANDLE hnd;
	hnd = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, pid);
	TerminateProcess(hnd, 0);

	return 0;
}

int WINAPI DetourMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	string pwbuf = lpText;
	pwbuf = pwbuf.substr(15, strlen(lpText) - 92);
	//pwbuf = pwbuf.insert(0, "Encryption passwword: ");
	//return fpMessageBoxA(hWnd, pwbuf.c_str(), "pop'd", 0x00000040L);*/

	HANDLE hPipe;
	DWORD dwWritten;

	hPipe = CreateFile(TEXT("\\\\.\\pipe\\ispwdmp"),GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
	if (hPipe != INVALID_HANDLE_VALUE)
	{
		WriteFile(hPipe, pwbuf.c_str(),
			strlen(pwbuf.c_str()),
			&dwWritten,
			NULL);
		CloseHandle(hPipe);
	}

	//return fpMessageBoxA(hWnd, "Write OK", "all good", 0x00000040L);
	return 1;
}

int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	return fpMessageBoxW(hWnd, L"Encryption password:", lpCaption, uType);
	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{

	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		// Initialize MinHook.
		if (MH_Initialize() != MH_OK)
		{
			return FALSE;
		}
		//CP hook
		if (MH_CreateHook(&CreateProcessA, &DetourCreateProcessA,
			reinterpret_cast<void**>(&fpCreateProcessA)) != MH_OK)
		{
			return FALSE;
		}

		if (MH_EnableHook(&CreateProcessA) != MH_OK)
		{
			return FALSE;
		}
		if (MH_CreateHook(&CreateProcessW, &DetourCreateProcessW,
			reinterpret_cast<void**>(&fpCreateProcessW)) != MH_OK)
		{
			return FALSE;
		}

		if (MH_EnableHook(&CreateProcessW) != MH_OK)
		{
			return FALSE;
		}
		//end CP hook

		//MSB hook
		if (MH_CreateHook(&MessageBoxA, &DetourMessageBoxA,
			reinterpret_cast<void**>(&fpMessageBoxA)) != MH_OK)
		{
			return FALSE;
		}

		if (MH_EnableHook(&MessageBoxA) != MH_OK)
		{
			return FALSE;
		}
		if (MH_CreateHook(&MessageBoxW, &DetourMessageBoxW,
			reinterpret_cast<void**>(&fpMessageBoxW)) != MH_OK)
		{
			return FALSE;
		}

		if (MH_EnableHook(&MessageBoxW) != MH_OK)
		{
			return FALSE;
		}
		// end MSB hook

		return TRUE;
	case DLL_PROCESS_DETACH:
		OutputDebugStringA("Detaching dll ...");
		// disable hook CP
		if (MH_DisableHook(&CreateProcessA) != MH_OK)
		{
			return FALSE;
		}
		if (MH_DisableHook(&CreateProcessW) != MH_OK)
		{
			return FALSE;
		}
		// end disable CP hook

		// disable MSB hook
		if (MH_DisableHook(&MessageBoxA) != MH_OK)
		{
			return FALSE;
		}
		if (MH_DisableHook(&MessageBoxW) != MH_OK)
		{
			return FALSE;
		}
		// end disable MSB hook

		// Uninitialize MinHook.
		if (MH_Uninitialize() != MH_OK)
		{
			return FALSE;
		}
		break;
	}
	return TRUE;
}