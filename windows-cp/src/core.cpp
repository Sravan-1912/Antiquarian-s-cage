// Antiquarian's Cage credential provider - core logic. See core.h.
#include "core.h"

#include <bcrypt.h>
#include <sddl.h>
#include <wincrypt.h>
#define SECURITY_WIN32
#include <ntsecapi.h>
#include <security.h>
#include <cstdarg>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")

namespace cage {

void WipeString(std::wstring& s) {
    if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
}

// ------------------------------------------------------------------------------------------- utf-8
std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring FromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

// ------------------------------------------------------------------------------------------- json
std::string JsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; sprintf_s(b, "\\u%04x", c); o += b; }
                else o += (char)c;
        }
    }
    return o;
}

// Finds the position just after `"key":` (whitespace tolerant) at nesting depth 1, or npos.
static size_t FindValue(const std::string& j, const char* key) {
    std::string needle = std::string("\"") + key + "\"";
    int depth = 0;
    bool inStr = false;
    for (size_t i = 0; i < j.size(); ++i) {
        char c = j[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '{' || c == '[') { ++depth; continue; }
        if (c == '}' || c == ']') { --depth; continue; }
        if (c == '"') {
            if (depth == 1 && j.compare(i, needle.size(), needle) == 0) {
                size_t k = i + needle.size();
                while (k < j.size() && isspace((unsigned char)j[k])) ++k;
                if (k < j.size() && j[k] == ':') {
                    ++k;
                    while (k < j.size() && isspace((unsigned char)j[k])) ++k;
                    return k;
                }
            }
            inStr = true;
        }
    }
    return std::string::npos;
}

bool JsonGetString(const std::string& j, const char* key, std::string& out) {
    size_t p = FindValue(j, key);
    if (p == std::string::npos || p >= j.size() || j[p] != '"') return false;
    out.clear();
    for (size_t i = p + 1; i < j.size(); ++i) {
        char c = j[i];
        if (c == '"') return true;
        if (c != '\\') { out += c; continue; }
        if (++i >= j.size()) return false;
        switch (j[i]) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'u': {
                if (i + 4 >= j.size()) return false;
                unsigned cp = (unsigned)strtoul(j.substr(i + 1, 4).c_str(), nullptr, 16);
                i += 4;
                std::wstring w(1, (wchar_t)cp);
                out += ToUtf8(w);
                break;
            }
            default: return false;
        }
    }
    return false;
}

bool JsonGetInt(const std::string& j, const char* key, long long& out) {
    size_t p = FindValue(j, key);
    if (p == std::string::npos || p >= j.size() || !(isdigit((unsigned char)j[p]) || j[p] == '-')) return false;
    out = _strtoi64(j.c_str() + p, nullptr, 10);
    return true;
}

bool JsonGetBool(const std::string& j, const char* key, bool& out) {
    size_t p = FindValue(j, key);
    if (p == std::string::npos) return false;
    if (j.compare(p, 4, "true") == 0) { out = true; return true; }
    if (j.compare(p, 5, "false") == 0) { out = false; return true; }
    return false;
}

// ------------------------------------------------------------------------------------------- base64
std::string Base64Encode(const BYTE* p, size_t n) {
    DWORD len = 0;
    CryptBinaryToStringA(p, (DWORD)n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
    std::string s(len, '\0');
    CryptBinaryToStringA(p, (DWORD)n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &s[0], &len);
    s.resize(len);
    return s;
}

bool Base64Decode(const std::string& s, SecureBytes& out) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr)) return false;
    out = SecureBytes(len);
    return CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64, out.data.data(), &len, nullptr, nullptr)
           && (out.data.resize(len), true);
}

// ------------------------------------------------------------------------------------------- crypto
HRESULT RandomBytes(BYTE* p, ULONG n) {
    NTSTATUS st = BCryptGenRandom(nullptr, p, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(st) ? S_OK : HRESULT_FROM_NT(st);
}

namespace {
struct Aes {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    ~Aes() { if (key) BCryptDestroyKey(key); if (alg) BCryptCloseAlgorithmProvider(alg, 0); }
    HRESULT Init(const SecureBytes& k) {
        if (k.data.size() != 32) return E_INVALIDARG;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(st)) return HRESULT_FROM_NT(st);
        st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(st)) return HRESULT_FROM_NT(st);
        st = BCryptGenerateSymmetricKey(alg, &key, nullptr, 0, (PUCHAR)k.data.data(), (ULONG)k.data.size(), 0);
        return BCRYPT_SUCCESS(st) ? S_OK : HRESULT_FROM_NT(st);
    }
};
}  // namespace

HRESULT SealPassword(const SecureBytes& key32, const std::wstring& password, const std::wstring& sid, SecureBytes& blob) {
    Aes aes;
    HRESULT hr = aes.Init(key32);
    if (FAILED(hr)) return hr;
    std::string aad = "cage-winpw-v1|" + ToUtf8(sid);
    ULONG ptLen = (ULONG)(password.size() * sizeof(wchar_t));
    blob = SecureBytes(12 + 16 + ptLen);
    BYTE* nonce = blob.data.data();
    BYTE* tag = nonce + 12;
    BYTE* ct = tag + 16;
    if (FAILED(hr = RandomBytes(nonce, 12))) return hr;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce; info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)aad.data(); info.cbAuthData = (ULONG)aad.size();
    info.pbTag = tag; info.cbTag = 16;
    ULONG out = 0;
    NTSTATUS st = BCryptEncrypt(aes.key, (PUCHAR)password.data(), ptLen, &info, nullptr, 0, ct, ptLen, &out, 0);
    return BCRYPT_SUCCESS(st) ? S_OK : HRESULT_FROM_NT(st);
}

HRESULT OpenPassword(const SecureBytes& key32, const SecureBytes& blob, const std::wstring& sid, std::wstring& password) {
    if (blob.data.size() < 28 || (blob.data.size() - 28) % sizeof(wchar_t)) return E_INVALIDARG;
    Aes aes;
    HRESULT hr = aes.Init(key32);
    if (FAILED(hr)) return hr;
    std::string aad = "cage-winpw-v1|" + ToUtf8(sid);
    ULONG ctLen = (ULONG)blob.data.size() - 28;
    SecureBytes pt(ctLen + sizeof(wchar_t));
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)blob.data.data(); info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)aad.data(); info.cbAuthData = (ULONG)aad.size();
    info.pbTag = (PUCHAR)blob.data.data() + 12; info.cbTag = 16;
    ULONG out = 0;
    NTSTATUS st = BCryptDecrypt(aes.key, (PUCHAR)blob.data.data() + 28, ctLen, &info, nullptr, 0, pt.data.data(), ctLen, &out, 0);
    if (!BCRYPT_SUCCESS(st)) return HRESULT_FROM_NT(st);  // wrong key, wrong SID or tampered blob
    WipeString(password);
    password.assign((const wchar_t*)pt.data.data(), out / sizeof(wchar_t));
    return S_OK;
}

// ------------------------------------------------------------------------------------------- store
HRESULT Store::Save(const std::wstring& sid, const SecureBytes& sealed) const {
    std::wstring entropy = L"cage-winpw|" + sid;
    DATA_BLOB in{(DWORD)sealed.data.size(), (BYTE*)sealed.data.data()};
    DATA_BLOB ent{(DWORD)(entropy.size() * sizeof(wchar_t)), (BYTE*)entropy.data()};
    DATA_BLOB prot{};
    if (!CryptProtectData(&in, L"Antiquarian's Cage phone sign-in", &ent, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &prot))
        return HRESULT_FROM_WIN32(GetLastError());
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, FALSE};
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (systemOnlyAcl) {  // protected DACL: SYSTEM full control only, inherited by nothing else
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;KA;;;SY)", SDDL_REVISION_1, &sd, nullptr)) {
            LocalFree(prot.pbData);
            return HRESULT_FROM_WIN32(GetLastError());
        }
        sa.lpSecurityDescriptor = sd;
    }
    HKEY k = nullptr;
    LSTATUS ls = RegCreateKeyExW(root, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE, systemOnlyAcl ? &sa : nullptr, &k, nullptr);
    if (sd) LocalFree(sd);
    if (ls == ERROR_SUCCESS) {
        ls = RegSetValueExW(k, sid.c_str(), 0, REG_BINARY, prot.pbData, prot.cbData);
        RegCloseKey(k);
    }
    SecureZeroMemory(prot.pbData, prot.cbData);
    LocalFree(prot.pbData);
    return HRESULT_FROM_WIN32(ls);
}

HRESULT Store::Load(const std::wstring& sid, SecureBytes& sealed) const {
    HKEY k = nullptr;
    LSTATUS ls = RegOpenKeyExW(root, path.c_str(), 0, KEY_QUERY_VALUE, &k);
    if (ls != ERROR_SUCCESS) return HRESULT_FROM_WIN32(ls);
    DWORD type = 0, size = 0;
    ls = RegQueryValueExW(k, sid.c_str(), nullptr, &type, nullptr, &size);
    if (ls != ERROR_SUCCESS || type != REG_BINARY) { RegCloseKey(k); return HRESULT_FROM_WIN32(ls ? ls : ERROR_INVALID_DATA); }
    SecureBytes prot(size);
    ls = RegQueryValueExW(k, sid.c_str(), nullptr, &type, prot.data.data(), &size);
    RegCloseKey(k);
    if (ls != ERROR_SUCCESS) return HRESULT_FROM_WIN32(ls);
    std::wstring entropy = L"cage-winpw|" + sid;
    DATA_BLOB in{size, prot.data.data()};
    DATA_BLOB ent{(DWORD)(entropy.size() * sizeof(wchar_t)), (BYTE*)entropy.data()};
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return HRESULT_FROM_WIN32(GetLastError());
    sealed = SecureBytes(out.cbData);
    memcpy(sealed.data.data(), out.pbData, out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return S_OK;
}

HRESULT Store::Remove(const std::wstring& sid) const {
    HKEY k = nullptr;
    LSTATUS ls = RegOpenKeyExW(root, path.c_str(), 0, KEY_SET_VALUE, &k);
    if (ls != ERROR_SUCCESS) return HRESULT_FROM_WIN32(ls);
    ls = RegDeleteValueW(k, sid.c_str());
    RegCloseKey(k);
    return HRESULT_FROM_WIN32(ls);
}

// ------------------------------------------------------------------------------------------- accounts
void SplitUser(const std::wstring& input, std::wstring& domain, std::wstring& user) {
    size_t p = input.find(L'\\');
    wchar_t comp[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD n = ARRAYSIZE(comp);
    GetComputerNameW(comp, &n);
    if (p == std::wstring::npos) { domain = comp; user = input; return; }
    domain = input.substr(0, p);
    user = input.substr(p + 1);
    if (domain == L".") domain = comp;
}

HRESULT LookupSid(const std::wstring& domain, const std::wstring& user, std::wstring& sid) {
    std::wstring full = domain + L"\\" + user;
    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuf);
    wchar_t dom[256];
    DWORD domSize = ARRAYSIZE(dom);
    SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, full.c_str(), sidBuf, &sidSize, dom, &domSize, &use))
        return HRESULT_FROM_WIN32(GetLastError());
    if (use != SidTypeUser) return HRESULT_FROM_WIN32(ERROR_NO_SUCH_USER);
    LPWSTR s = nullptr;
    if (!ConvertSidToStringSidW(sidBuf, &s)) return HRESULT_FROM_WIN32(GetLastError());
    sid = s;
    LocalFree(s);
    return S_OK;
}

HRESULT VerifyPassword(const std::wstring& domain, const std::wstring& user, const std::wstring& password) {
    HANDLE tok = nullptr;
    if (!LogonUserW(user.c_str(), domain.c_str(), password.c_str(), LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT, &tok))
        return HRESULT_FROM_WIN32(GetLastError());
    CloseHandle(tok);
    return S_OK;
}

// ------------------------------------------------------------------------------------------- relay pipe
HRESULT RelayCall(const std::string& request, RelayReply& reply, DWORD timeoutMs, const wchar_t* pipeName) {
    reply = RelayReply{};
    if (!WaitNamedPipeW(pipeName, timeoutMs)) return HRESULT_FROM_WIN32(GetLastError());
    HANDLE h = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (h == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
    DWORD mode = PIPE_READMODE_MESSAGE;
    HRESULT hr = S_OK;
    if (!SetNamedPipeHandleState(h, &mode, nullptr, nullptr)) hr = HRESULT_FROM_WIN32(GetLastError());
    DWORD written = 0;
    if (SUCCEEDED(hr) && !WriteFile(h, request.data(), (DWORD)request.size(), &written, nullptr))
        hr = HRESULT_FROM_WIN32(GetLastError());
    if (SUCCEEDED(hr)) {
        char buf[4096];
        for (;;) {
            DWORD got = 0;
            BOOL ok = ReadFile(h, buf, sizeof(buf), &got, nullptr);
            reply.raw.append(buf, got);
            if (ok) break;
            if (GetLastError() != ERROR_MORE_DATA) { hr = HRESULT_FROM_WIN32(GetLastError()); break; }
            if (reply.raw.size() > (1 << 20)) { hr = E_UNEXPECTED; break; }
        }
        SecureZeroMemory(buf, sizeof(buf));
    }
    CloseHandle(h);
    if (FAILED(hr)) return hr;
    bool ok = false;
    if (!JsonGetBool(reply.raw, "ok", ok)) return E_UNEXPECTED;
    reply.ok = ok;
    if (!ok) {
        JsonGetString(reply.raw, "code", reply.code);
        JsonGetString(reply.raw, "message", reply.message);
    }
    return S_OK;
}

// ------------------------------------------------------------------------------------------- serialization
HRESULT PackInteractiveLogon(const std::wstring& domain, const std::wstring& user, const std::wstring& password,
                             bool unlock, BYTE** out, DWORD* outSize) {
    *out = nullptr;
    *outSize = 0;
    const USHORT dl = (USHORT)(domain.size() * sizeof(wchar_t));
    const USHORT ul = (USHORT)(user.size() * sizeof(wchar_t));
    const USHORT pl = (USHORT)(password.size() * sizeof(wchar_t));
    DWORD total = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + dl + ul + pl;
    BYTE* buf = (BYTE*)CoTaskMemAlloc(total);
    if (!buf) return E_OUTOFMEMORY;
    ZeroMemory(buf, total);
    auto* kiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)buf;
    KERB_INTERACTIVE_LOGON& l = kiul->Logon;
    l.MessageType = unlock ? KerbWorkstationUnlockLogon : KerbInteractiveLogon;
    BYTE* p = buf + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    // In the packed form, Buffer holds the offset from the start of the structure (LSA relocates it).
    auto put = [&](UNICODE_STRING& us, const std::wstring& s, USHORT len) {
        us.Length = len;
        us.MaximumLength = len;
        us.Buffer = (PWSTR)(p - buf);
        memcpy(p, s.data(), len);
        p += len;
    };
    put(l.LogonDomainName, domain, dl);
    put(l.UserName, user, ul);
    put(l.Password, password, pl);
    *out = buf;
    *outSize = total;
    return S_OK;
}

HRESULT NegotiatePackage(ULONG* package) {
    HANDLE lsa = nullptr;
    NTSTATUS st = LsaConnectUntrusted(&lsa);
    if (st != STATUS_SUCCESS) return HRESULT_FROM_NT(st);
    LSA_STRING name;
    name.Buffer = (PCHAR)NEGOSSP_NAME_A;
    name.Length = (USHORT)strlen(NEGOSSP_NAME_A);
    name.MaximumLength = name.Length + 1;
    st = LsaLookupAuthenticationPackage(lsa, &name, package);
    LsaDeregisterLogonProcess(lsa);
    return st == STATUS_SUCCESS ? S_OK : HRESULT_FROM_NT(st);
}

// ------------------------------------------------------------------------------------------- log
void Log(const wchar_t* fmt, ...) {
    wchar_t dir[MAX_PATH];
    if (!ExpandEnvironmentStringsW(L"%ProgramData%\\AntiquariansCage", dir, MAX_PATH)) return;
    CreateDirectoryW(dir, nullptr);
    std::wstring file = std::wstring(dir) + L"\\credential-provider.log";
    FILE* f = nullptr;
    if (_wfopen_s(&f, file.c_str(), L"a, ccs=UTF-8") != 0 || !f) return;
    SYSTEMTIME t;
    GetSystemTime(&t);
    fwprintf(f, L"%04d-%02d-%02dT%02d:%02d:%02dZ [%lu] ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond,
             GetCurrentProcessId());
    va_list ap;
    va_start(ap, fmt);
    vfwprintf(f, fmt, ap);
    va_end(ap);
    fputwc(L'\n', f);
    fclose(f);
}

}  // namespace cage
