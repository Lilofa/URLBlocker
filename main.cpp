#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <set>
#include <thread>
#include <mutex>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

set<string> blockedDomains;
mutex mtx;
bool firewallActive = false;

string Now() {
    time_t t = time(nullptr);
    char buf[64];
    ctime_s(buf, sizeof(buf), &t);
    string s(buf);
    if (!s.empty() && s.back() == '\n') s.pop_back();
    return s;
}

// Extract domain from URL
string ExtractDomain(const string& input) {
    string url = input;
    
    // Remove http:// or https://
    size_t pos = url.find("://");
    if (pos != string::npos) {
        url = url.substr(pos + 3);
    }
    
    // Remove path
    pos = url.find('/');
    if (pos != string::npos) {
        url = url.substr(0, pos);
    }
    
    // Remove port
    pos = url.find(':');
    if (pos != string::npos) {
        url = url.substr(0, pos);
    }
    
    return url;
}

string GetIP(const string& domain) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return "";
    struct hostent* h = gethostbyname(domain.c_str());
    WSACleanup();
    if (!h || !h->h_addr_list[0]) return "";
    struct in_addr addr;
    memcpy(&addr, h->h_addr_list[0], sizeof(addr));
    return string(inet_ntoa(addr));
}

bool AddRule(const string& name, const string& ip) {
    string cmd = "netsh advfirewall firewall add rule name=\"" + name + 
                 "\" dir=out action=block remoteip=" + ip + " > nul";
    return system(cmd.c_str()) == 0;
}

bool RemoveRule(const string& name) {
    string cmd = "netsh advfirewall firewall delete rule name=\"" + name + "\" > nul";
    return system(cmd.c_str()) == 0;
}

void Block(const string& domain) {
    string ip = GetIP(domain);
    if (ip.empty()) return;
    AddRule("BLOCK_" + domain, ip);
}

void Unblock(const string& domain) {
    RemoveRule("BLOCK_" + domain);
}

void BlockAll() {
    lock_guard<mutex> lock(mtx);
    for (const string& d : blockedDomains) Block(d);
}

void UnblockAll() {
    lock_guard<mutex> lock(mtx);
    for (const string& d : blockedDomains) Unblock(d);
}

HWND hList, hLog, hEdit, hStatus;

void AddLog(const string& msg) {
    if (hLog) {
        string line = "[" + Now() + "] " + msg + "\r\n";
        int len = GetWindowTextLengthA(hLog);
        SendMessageA(hLog, EM_SETSEL, len, len);
        SendMessageA(hLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    }
}

void UpdateList() {
    lock_guard<mutex> lock(mtx);
    SendMessageA(hList, LB_RESETCONTENT, 0, 0);
    for (const string& d : blockedDomains)
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)d.c_str());
    char buf[128];
    sprintf_s(buf, "Rules: %d | Status: %s", (int)blockedDomains.size(),
              firewallActive ? "ACTIVE" : "STOPPED");
    SetWindowTextA(hStatus, buf);
}

void AddDomain(const string& input) {
    string domain = ExtractDomain(input);
    if (domain.empty()) {
        AddLog("ERROR: Empty domain");
        return;
    }
    
    string ip = GetIP(domain);
    if (ip.empty()) {
        AddLog("ERROR: Cannot resolve " + domain);
        return;
    }
    
    {
        lock_guard<mutex> lock(mtx);
        if (blockedDomains.find(domain) != blockedDomains.end()) {
            AddLog("Domain already in list: " + domain);
            return;
        }
        blockedDomains.insert(domain);
    }
    
    if (firewallActive) Block(domain);
    UpdateList();
    AddLog("ADDED: " + domain + " (" + ip + ")");
}

void RemoveDomain(const string& domain) {
    {
        lock_guard<mutex> lock(mtx);
        if (blockedDomains.find(domain) == blockedDomains.end()) return;
        blockedDomains.erase(domain);
    }
    if (firewallActive) Unblock(domain);
    UpdateList();
    AddLog("REMOVED: " + domain);
}

void StartFirewall() {
    if (firewallActive) return;
    firewallActive = true;
    BlockAll();
    AddLog("=== FIREWALL STARTED ===");
    UpdateList();
}

void StopFirewall() {
    if (!firewallActive) return;
    firewallActive = false;
    UnblockAll();
    AddLog("=== FIREWALL STOPPED ===");
    UpdateList();
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindowA("STATIC", "URL BLOCKER (Windows Firewall)", 
                          WS_CHILD | WS_VISIBLE | SS_CENTER, 10, 5, 460, 25, hwnd, NULL, NULL, NULL);
            
            CreateWindowA("BUTTON", "START", WS_CHILD | WS_VISIBLE, 
                          10, 35, 100, 35, hwnd, (HMENU)1, NULL, NULL);
            CreateWindowA("BUTTON", "STOP", WS_CHILD | WS_VISIBLE, 
                          120, 35, 100, 35, hwnd, (HMENU)2, NULL, NULL);
            
            CreateWindowA("STATIC", "Blocked Domains:", WS_CHILD | WS_VISIBLE, 
                          10, 80, 200, 20, hwnd, NULL, NULL, NULL);
            hList = CreateWindowA("LISTBOX", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL,
                                  10, 100, 220, 200, hwnd, NULL, NULL, NULL);
            
            hEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                  10, 310, 220, 25, hwnd, NULL, NULL, NULL);
            CreateWindowA("BUTTON", "ADD", WS_CHILD | WS_VISIBLE,
                          10, 340, 100, 30, hwnd, (HMENU)3, NULL, NULL);
            CreateWindowA("BUTTON", "REMOVE", WS_CHILD | WS_VISIBLE,
                          120, 340, 100, 30, hwnd, (HMENU)4, NULL, NULL);
            
            CreateWindowA("STATIC", "Log:", WS_CHILD | WS_VISIBLE, 
                          250, 80, 200, 20, hwnd, NULL, NULL, NULL);
            hLog = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                                 250, 100, 220, 270, hwnd, NULL, NULL, NULL);
            
            hStatus = CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE,
                                    0, 380, 480, 22, hwnd, NULL, NULL, NULL);
            
            AddLog("Program started. Click START.");
            AddLog("Enter domain or full URL (e.g., youtube.com or https://youtube.com)");
            UpdateList();
            break;
        }
        case WM_COMMAND:
            if (LOWORD(w) == 1) {
                StartFirewall();
                EnableWindow(GetDlgItem(hwnd, 1), FALSE);
                EnableWindow(GetDlgItem(hwnd, 2), TRUE);
            } else if (LOWORD(w) == 2) {
                StopFirewall();
                EnableWindow(GetDlgItem(hwnd, 1), TRUE);
                EnableWindow(GetDlgItem(hwnd, 2), FALSE);
            } else if (LOWORD(w) == 3) {
                char buf[256] = {0};
                GetWindowTextA(hEdit, buf, 255);
                if (strlen(buf) > 0) {
                    AddDomain(buf);
                    SetWindowTextA(hEdit, "");
                }
            } else if (LOWORD(w) == 4) {
                int sel = SendMessageA(hList, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR) {
                    char buf[256] = {0};
                    SendMessageA(hList, LB_GETTEXT, sel, (LPARAM)buf);
                    RemoveDomain(buf);
                }
            }
            break;
        case WM_DESTROY:
            if (firewallActive) StopFirewall();
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, w, l);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nShow) {
    WNDCLASSA wc = { 0, WndProc, 0, 0, hInst, NULL, LoadCursor(NULL, IDC_ARROW),
                     (HBRUSH)(COLOR_WINDOW + 1), NULL, "URLBlocker" };
    RegisterClassA(&wc);
    
    HWND hwnd = CreateWindowExA(0, "URLBlocker", "URL Blocker",
                                WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
                                CW_USEDEFAULT, CW_USEDEFAULT, 500, 440,
                                NULL, NULL, hInst, NULL);
    if (!hwnd) return 0;
    
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
