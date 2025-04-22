#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

class MemoryManager
{
public:
    DWORD GetProcessIdByName(const std::wstring& processName) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

        if (snapshot == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[-] CreateToolhelp32Snapshot baþarýsýz oldu. Hata kodu: " << GetLastError() << std::endl;
            return 0;
        }

        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (std::wstring(entry.szExeFile) == processName) {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        else {
            std::wcerr << L"[-] Process32FirstW baþarýsýz oldu. Hata kodu: " << GetLastError() << std::endl;
        }

        CloseHandle(snapshot);
        std::wcerr << L"[-] Proses bulunamadý: " << processName << std::endl;
        return 0;
    }

    HANDLE GetProcessHandle(DWORD processId) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (handle == NULL) {
            std::cerr << "[-] OpenProcess baþarýsýz oldu. Hata kodu: " << GetLastError() << std::endl;
        }
        return handle;
    }

    template <typename T>
    T ReadMemory(HANDLE processHandle, uintptr_t address) {
        T value;
        SIZE_T bytesRead;
        if (!ReadProcessMemory(processHandle, (LPCVOID)address, &value, sizeof(T), &bytesRead) || bytesRead != sizeof(T)) {
            return T{};
        }
        return value;
    }

    template <typename T>
    bool WriteMemory(HANDLE processHandle, uintptr_t address, T value) {
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(processHandle, (LPVOID)address, &value, sizeof(T), &bytesWritten) || bytesWritten != sizeof(T)) {
            return false;
        }
        return true;
    }

    uintptr_t GetModuleBaseAddress(DWORD processId, const std::wstring& moduleName) {
        uintptr_t moduleBaseAddress = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

        if (snapshot == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[-] CreateToolhelp32Snapshot (Module) baþarýsýz oldu. Hata kodu: " << GetLastError() << std::endl;
            return 0;
        }

        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(snapshot, &moduleEntry)) {
            do {
                if (std::wstring(moduleEntry.szModule) == moduleName) {
                    moduleBaseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(snapshot, &moduleEntry));
        }
        else {
            std::wcerr << L"[-] Module32FirstW baþarýsýz oldu. Hata kodu: " << GetLastError() << std::endl;
        }


        CloseHandle(snapshot);

        if (moduleBaseAddress == 0) {
            std::wcerr << L"[-] Modül bulunamadý: " << moduleName << std::endl;
        }

        return moduleBaseAddress;
    }

    std::string ReadString(HANDLE processHandle, uintptr_t address, size_t maxLength = 256) {
        std::vector<char> buffer(maxLength);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), maxLength, &bytesRead)) {
            return "";
        }

        size_t nullPos = std::string::npos;
        for (size_t i = 0; i < bytesRead; ++i) {
            if (buffer[i] == '\0') {
                nullPos = i;
                break;
            }
        }

        if (nullPos != std::string::npos) {
            return std::string(buffer.data(), nullPos);
        }
        else {
            return std::string(buffer.data(), bytesRead);
        }
    }

    uintptr_t FindDMAAddy(HANDLE processHandle, uintptr_t baseAddress, const std::vector<uintptr_t>& offsets) {
        uintptr_t addr = baseAddress;
        for (size_t i = 0; i < offsets.size(); ++i) {
            addr = ReadMemory<uintptr_t>(processHandle, addr);
            if (addr == 0) {
                return 0;
            }
            if (i < offsets.size() - 1) {
                addr += offsets[i];
            }
            else {
                addr += offsets[i];
            }

        }
        return addr;
    }

    bool WriteBytes(HANDLE processHandle, uintptr_t address, const std::vector<BYTE>& bytes) {
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(processHandle, (LPVOID)address, bytes.data(), bytes.size(), &bytesWritten) || bytesWritten != bytes.size()) {
            return false;
        }
        return true;
    }

    bool ProtectMemory(HANDLE processHandle, uintptr_t address, size_t size, DWORD newProtect, DWORD& oldProtect) {
        if (!VirtualProtectEx(processHandle, (LPVOID)address, size, newProtect, &oldProtect)) {
            return false;
        }
        return true;
    }
	bool RestoreMemoryProtection(HANDLE processHandle, uintptr_t address, size_t size, DWORD oldProtect) {
		DWORD temp;
		if (!VirtualProtectEx(processHandle, (LPVOID)address, size, oldProtect, &temp)) {
			return false;
		}
		return true;
	}

};
