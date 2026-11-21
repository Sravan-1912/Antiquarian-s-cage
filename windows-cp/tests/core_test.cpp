// Unit tests for the credential provider core. Safe to run on any machine: nothing is registered with LogonUI,
// the store test uses HKCU\Software\AntiquariansCageTest, and no password is ever verified against Windows.
#include "../src/core.h"

#define SECURITY_WIN32
#include <ntsecapi.h>
#include <cstdio>

using namespace cage;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { ++failures; wprintf(L"FAIL  %hs:%d  %hs\n", __FILE__, __LINE__, #c); } else { wprintf(L"PASS  %hs\n", #c); } } while (0)

static SecureBytes RandomKey() {
    SecureBytes k(32);
    RandomBytes(k.data.data(), 32);
    return k;
}

int wmain() {
    // ---- JSON
    std::string j = R"({"ok": true, "request_id": "a-1", "number": 42, "message": "Line \"one\"\né", "nested": {"number": 7}})";
    bool ok = false; long long n = 0; std::string s;
    CHECK(JsonGetBool(j, "ok", ok) && ok);
    CHECK(JsonGetInt(j, "number", n) && n == 42);  // top level, not the nested one
    CHECK(JsonGetString(j, "request_id", s) && s == "a-1");
    CHECK(JsonGetString(j, "message", s) && s == "Line \"one\"\n\xc3\xa9");
    CHECK(!JsonGetString(j, "missing", s));
    CHECK(!JsonGetString(j, "number", s));  // wrong type
    std::string esc = std::string("{\"v\":\"") + JsonEscape("a\"b\\c\n") + "\"}";
    CHECK(JsonGetString(esc, "v", s) && s == "a\"b\\c\n");

    // ---- base64
    BYTE raw[5] = {0, 1, 2, 250, 255};
    SecureBytes back;
    CHECK(Base64Decode(Base64Encode(raw, 5), back) && back.data.size() == 5 && memcmp(back.data.data(), raw, 5) == 0);

    // ---- seal / open
    const std::wstring sid = L"S-1-5-21-1-2-3-1001";
    SecureBytes key = RandomKey(), blob;
    std::wstring pw = L"Correct-Horse-Battery-\x00e9", outPw;
    CHECK(SUCCEEDED(SealPassword(key, pw, sid, blob)));
    CHECK(SUCCEEDED(OpenPassword(key, blob, sid, outPw)) && outPw == pw);
    SecureBytes wrong = RandomKey();
    CHECK(FAILED(OpenPassword(wrong, blob, sid, outPw)));              // wrong key
    CHECK(FAILED(OpenPassword(key, blob, L"S-1-5-21-1-2-3-500", outPw)));  // bound to the account SID
    blob.data[40] ^= 1;
    CHECK(FAILED(OpenPassword(key, blob, sid, outPw)));                // tampered

    // ---- store (machine DPAPI; test location, no SYSTEM-only ACL so a normal user can run this)
    Store st;
    st.root = HKEY_CURRENT_USER;
    st.path = L"Software\\AntiquariansCageTest";
    st.systemOnlyAcl = false;
    SecureBytes sealed, loaded;
    SealPassword(key, pw, sid, sealed);
    CHECK(SUCCEEDED(st.Save(sid, sealed)));
    CHECK(SUCCEEDED(st.Load(sid, loaded)) && loaded.data == sealed.data);
    CHECK(SUCCEEDED(st.Remove(sid)));
    CHECK(FAILED(st.Load(sid, loaded)));
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\AntiquariansCageTest");

    // ---- accounts
    std::wstring d, u;
    SplitUser(L"CORP\\ada", d, u);
    CHECK(d == L"CORP" && u == L"ada");
    SplitUser(L".\\ada", d, u);
    wchar_t comp[64]; DWORD cn = 64; GetComputerNameW(comp, &cn);
    CHECK(d == comp && u == L"ada");
    wchar_t me[256]; DWORD mn = 256; GetUserNameW(me, &mn);
    std::wstring mySid;
    SplitUser(me, d, u);
    CHECK(SUCCEEDED(LookupSid(d, u, mySid)) && mySid.rfind(L"S-1-5-", 0) == 0);
    CHECK(FAILED(LookupSid(d, L"no-such-user-cage-test", mySid)));

    // ---- serialization layout
    BYTE* buf = nullptr; DWORD size = 0;
    CHECK(SUCCEEDED(PackInteractiveLogon(L"PC", L"ada", L"pw123", true, &buf, &size)));
    auto* k = (KERB_INTERACTIVE_UNLOCK_LOGON*)buf;
    CHECK(k->Logon.MessageType == KerbWorkstationUnlockLogon);
    CHECK(k->Logon.UserName.Length == 6 &&
          memcmp(buf + (ULONG_PTR)k->Logon.UserName.Buffer, L"ada", 6) == 0);
    CHECK(memcmp(buf + (ULONG_PTR)k->Logon.Password.Buffer, L"pw123", 10) == 0);
    CHECK(size == sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 4 + 6 + 10);
    SecureZeroMemory(buf, size);
    CoTaskMemFree(buf);
    ULONG pkg = 0;
    CHECK(SUCCEEDED(NegotiatePackage(&pkg)));

    // ---- relay unavailable is reported, not hung
    RelayReply r;
    CHECK(FAILED(RelayCall("{\"op\":\"ping\"}", r, 200, L"\\\\.\\pipe\\AntiquariansCageNoSuchPipe")));

    wprintf(L"\n%s (%d failure%s)\n", failures ? L"FAILED" : L"ALL PASSED", failures, failures == 1 ? L"" : L"s");
    return failures ? 1 : 0;
}
