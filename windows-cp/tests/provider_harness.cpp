// Loads CageCredentialProvider.dll like LogonUI would (DllGetClassObject -> ICredentialProvider) WITHOUT registering
// it, and drives the tile's error paths. Safe on any machine: it never produces a credential for a real account.
#include <windows.h>
#include <credentialprovider.h>
#include <cstdio>
#include <string>

static int failures = 0;
#define CHECK(c, what) do { if (!(c)) { ++failures; wprintf(L"FAIL  %s\n", what); } else wprintf(L"PASS  %s\n", what); } while (0)

static const CLSID CLSID_CageProvider = {0x20c827da, 0x2d25, 0x4842, {0xb9, 0x2d, 0x57, 0xfb, 0x49, 0x24, 0xf8, 0x7b}};
enum { FI_TITLE, FI_NUMBER, FI_STATUS, FI_USERNAME, FI_PASSWORD, FI_SETUP_LINK, FI_SUBMIT, FI_COUNT };

static std::wstring Submit(ICredentialProviderCredential* c, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* resp) {
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cs{};
    PWSTR status = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon;
    c->GetSerialization(resp, &cs, &status, &icon);
    std::wstring s = status ? status : L"";
    CoTaskMemFree(status);
    if (cs.rgbSerialization) CoTaskMemFree(cs.rgbSerialization);
    return s;
}

int wmain(int argc, wchar_t** argv) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    HMODULE dll = LoadLibraryW(argc > 1 ? argv[1] : L"out\\CageCredentialProvider.dll");
    CHECK(dll != nullptr, L"DLL loads");
    if (!dll) return 1;
    auto getClass = (HRESULT(WINAPI*)(REFCLSID, REFIID, void**))GetProcAddress(dll, "DllGetClassObject");
    IClassFactory* f = nullptr;
    CHECK(SUCCEEDED(getClass(CLSID_CageProvider, IID_IClassFactory, (void**)&f)), L"class factory");
    ICredentialProvider* p = nullptr;
    CHECK(SUCCEEDED(f->CreateInstance(nullptr, IID_ICredentialProvider, (void**)&p)), L"provider instance");
    f->Release();

    CHECK(p->SetUsageScenario(CPUS_CREDUI, 0) == E_NOTIMPL, L"not offered in CredUI / UAC prompts");
    CHECK(p->SetUsageScenario(CPUS_CHANGE_PASSWORD, 0) == E_NOTIMPL, L"not offered for change-password");
    CHECK(SUCCEEDED(p->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0)), L"offered on unlock");

    DWORD n = 0, def = 0;
    BOOL autoLogon = TRUE;
    p->GetFieldDescriptorCount(&n);
    CHECK(n == FI_COUNT, L"7 fields");
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* d = nullptr;
    p->GetFieldDescriptorAt(FI_PASSWORD, &d);
    CHECK(d && d->cpft == CPFT_PASSWORD_TEXT, L"password field is a masked password field");
    if (d) { CoTaskMemFree(d->pszLabel); CoTaskMemFree(d); }
    p->GetCredentialCount(&n, &def, &autoLogon);
    CHECK(n == 1 && def == CREDENTIAL_PROVIDER_NO_DEFAULT && !autoLogon, L"one tile, never auto-selected before approval");

    ICredentialProviderCredential* c = nullptr;
    p->GetCredentialAt(0, &c);
    CREDENTIAL_PROVIDER_FIELD_STATE st;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE is;
    c->GetFieldState(FI_PASSWORD, &st, &is);
    CHECK(st == CPFS_HIDDEN, L"password hidden outside setup");
    c->CommandLinkClicked(FI_SETUP_LINK);
    c->GetFieldState(FI_PASSWORD, &st, &is);
    CHECK(st == CPFS_DISPLAY_IN_SELECTED_TILE, L"setup link reveals the password field");
    c->CommandLinkClicked(FI_SETUP_LINK);

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE resp;
    std::wstring s = Submit(c, &resp);
    CHECK(resp == CPGSR_NO_CREDENTIAL_NOT_FINISHED && s.find(L"user name") != std::wstring::npos, L"empty user name explained");

    c->SetStringValue(FI_USERNAME, L".\\no-such-user-cage-test");
    s = Submit(c, &resp);
    CHECK(resp == CPGSR_NO_CREDENTIAL_NOT_FINISHED && s.find(L"No Windows account") != std::wstring::npos, L"unknown account explained");

    wchar_t me[256]; DWORD mn = 256; GetUserNameW(me, &mn);
    c->SetStringValue(FI_USERNAME, me);
    s = Submit(c, &resp);
    CHECK(resp == CPGSR_NO_CREDENTIAL_NOT_FINISHED && s.find(L"not set up") != std::wstring::npos,
          L"real account without setup: told to set up, no credential produced");

    c->CommandLinkClicked(FI_SETUP_LINK);
    s = Submit(c, &resp);
    CHECK(resp == CPGSR_NO_CREDENTIAL_NOT_FINISHED && s.find(L"current Windows password") != std::wstring::npos,
          L"setup without password asks for it (no logon attempt made)");

    p->GetCredentialCount(&n, &def, &autoLogon);
    CHECK(!autoLogon, L"still no auto-logon");
    c->Release();
    p->Release();
    wprintf(L"\n%s (%d failure%s)\n", failures ? L"FAILED" : L"ALL PASSED", failures, failures == 1 ? L"" : L"s");
    return failures ? 1 : 0;
}
