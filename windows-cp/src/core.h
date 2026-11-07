// Antiquarian's Cage credential provider - core logic (no COM/UI), unit-tested by tests/core_test.cpp.
#pragma once
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <windows.h>
#include <objbase.h>
#include <string>
#include <vector>

namespace cage {

// ---------------------------------------------------------------- secure buffers
// Wipes on destruction. Passwords and keys only ever live in these.
struct SecureBytes {
    std::vector<BYTE> data;
    SecureBytes() = default;
    explicit SecureBytes(size_t n) : data(n) {}
    ~SecureBytes() { wipe(); }
    void wipe() { if (!data.empty()) SecureZeroMemory(data.data(), data.size()); data.clear(); }
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& o) noexcept : data(std::move(o.data)) {}
    SecureBytes& operator=(SecureBytes&& o) noexcept { wipe(); data = std::move(o.data); return *this; }
};

void WipeString(std::wstring& s);

// ---------------------------------------------------------------- JSON (tiny, for the relay protocol only)
std::string JsonEscape(const std::string& s);
// Extracts a top-level string / integer / bool value by key. Returns false if missing or the wrong type.
bool JsonGetString(const std::string& json, const char* key, std::string& out);
bool JsonGetInt(const std::string& json, const char* key, long long& out);
bool JsonGetBool(const std::string& json, const char* key, bool& out);

std::string ToUtf8(const std::wstring& w);
std::wstring FromUtf8(const std::string& s);

// ---------------------------------------------------------------- base64
std::string Base64Encode(const BYTE* p, size_t n);
bool Base64Decode(const std::string& s, SecureBytes& out);

// ---------------------------------------------------------------- crypto
HRESULT RandomBytes(BYTE* p, ULONG n);
// AES-256-GCM: blob = nonce(12) | tag(16) | ciphertext. Associated data binds the blob to the account SID.
HRESULT SealPassword(const SecureBytes& key32, const std::wstring& password, const std::wstring& sid, SecureBytes& blob);
HRESULT OpenPassword(const SecureBytes& key32, const SecureBytes& blob, const std::wstring& sid, std::wstring& password);

// ---------------------------------------------------------------- per-account store (HKLM, SYSTEM-only, machine DPAPI)
// root lets tests use a different (HKCU) location; production uses HKLM\SOFTWARE\AntiquariansCage\PhoneUnlock.
struct Store {
    HKEY root = HKEY_LOCAL_MACHINE;
    std::wstring path = L"SOFTWARE\\AntiquariansCage\\PhoneUnlock";
    bool systemOnlyAcl = true;
    HRESULT Save(const std::wstring& sid, const SecureBytes& sealed) const;
    HRESULT Load(const std::wstring& sid, SecureBytes& sealed) const;
    HRESULT Remove(const std::wstring& sid) const;
};

// ---------------------------------------------------------------- accounts
// "ada" -> (COMPUTERNAME, ada); "DOMAIN\ada" -> (DOMAIN, ada); ".\ada" -> (COMPUTERNAME, ada)
void SplitUser(const std::wstring& input, std::wstring& domain, std::wstring& user);
HRESULT LookupSid(const std::wstring& domain, const std::wstring& user, std::wstring& sid);
// Verifies a password without creating a session (LogonUserW, network logon type).
HRESULT VerifyPassword(const std::wstring& domain, const std::wstring& user, const std::wstring& password);

// ---------------------------------------------------------------- relay pipe
struct RelayReply {
    bool ok = false;
    std::string raw;      // full JSON (may contain a key - wipe when done)
    std::string code;     // error code when !ok
    std::string message;  // error text when !ok
};
// Sends one JSON request to \\.\pipe\AntiquariansCageUnlock and reads one reply.
HRESULT RelayCall(const std::string& request, RelayReply& reply, DWORD timeoutMs = 5000,
                  const wchar_t* pipeName = L"\\\\.\\pipe\\AntiquariansCageUnlock");

// ---------------------------------------------------------------- Kerberos serialization for LogonUI
// Packs KERB_INTERACTIVE_UNLOCK_LOGON for the given scenario (logon or workstation unlock) into one CoTaskMem buffer.
HRESULT PackInteractiveLogon(const std::wstring& domain, const std::wstring& user, const std::wstring& password,
                             bool unlock, BYTE** out, DWORD* outSize);
HRESULT NegotiatePackage(ULONG* package);

// ---------------------------------------------------------------- diagnostics (never secrets)
void Log(const wchar_t* fmt, ...);

}  // namespace cage
