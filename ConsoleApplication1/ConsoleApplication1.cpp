#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>

bool InjectDLL(const wchar_t* dllPath, DWORD processId) {
 // Get a handle to the target process
 HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
 if (!hProcess) {
    std::wcout << L"OpenProcess failed. Error: " << GetLastError() << std::endl;
    return false;
 }

 // Allocate memory in the target process for the DLL path
 void* pDllPath = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
 if (!pDllPath) {
    std::wcout << L"VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
    return false;
 }

 // Write the DLL path into the allocated memory
 if (!WriteProcessMemory(hProcess, pDllPath, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL)) {
    std::wcout << L"WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
    return false;
 }

 // Get the address of LoadLibraryW in kernel32.dll
 LPVOID pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW");
 if (!pLoadLibraryW) {
    std::wcout << L"GetProcAddress failed. Error: " << GetLastError() << std::endl;
    return false;
 }

 // Create a remote thread in the target process that calls LoadLibraryW with the DLL path as argument
 HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pDllPath, 0, NULL);
 if (!hThread) {
    std::wcout << L"CreateRemoteThread failed. Error: " << GetLastError() << std::endl;
    return false;
 }

 CloseHandle(hThread);
 CloseHandle(hProcess);

 return true;
}

int main() {
 std::wstring dllPath;
 std::wcout << L"Enter the path to the DLL: ";
 std::wcin >> dllPath;

 std::wstring exeName;
 std::wcout << L"Enter the name of the executable: ";
 std::wcin >> exeName;

 // Find the process ID of the target executable
 DWORD processId = 0;
 HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 if (hSnapshot != INVALID_HANDLE_VALUE) {
   PROCESSENTRY32 pe;
   pe.dwSize = sizeof(pe);
   if (Process32First(hSnapshot, &pe)) {
      do {
         if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
            processId = pe.th32ProcessID;
            break;
         }
      } while (Process32Next(hSnapshot, &pe));
   }
   CloseHandle(hSnapshot);
 }

 if (processId == 0) {
   std::wcout << L"Could not find the executable.\n";
   return 1;
 }

 if (InjectDLL(dllPath.c_str(), processId)) {
    std::wcout << L"DLL injection successful.\n";
 } else {
    std::wcout << L"DLL injection failed.\n";
 }

 return 0;
}