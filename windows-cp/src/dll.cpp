// COM plumbing: class factory, DLL exports and (un)registration of the credential provider.
#include "provider.h"

#include <new>
#include <string>

std::atomic<long> g_dllRefs{0};
static HINSTANCE g_module = nullptr;

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = inst;
        DisableThreadLibraryCalls(inst);
    }
    return TRUE;
}

class Factory : public IClassFactory {
public:
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) { *ppv = this; AddRef(); return S_OK; }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { long r = --refs_; if (!r) delete this; return r; }
    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* p = new (std::nothrow) CageProvider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override { lock ? ++g_dllRefs : --g_dllRefs; return S_OK; }
private:
    std::atomic<long> refs_{1};
};

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv) {
    if (clsid != CLSID_CageProvider) return CLASS_E_CLASSNOTAVAILABLE;
    auto* f = new (std::nothrow) Factory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

STDAPI DllCanUnloadNow() { return g_dllRefs == 0 ? S_OK : S_FALSE; }

static std::wstring ClsidString() {
    wchar_t s[64];
    StringFromGUID2(CLSID_CageProvider, s, ARRAYSIZE(s));
    return s;
}

static LSTATUS SetDefault(HKEY root, const std::wstring& path, const wchar_t* name, const std::wstring& value) {
    HKEY k = nullptr;
    LSTATUS ls = RegCreateKeyExW(root, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr);
    if (ls != ERROR_SUCCESS) return ls;
    ls = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value.c_str(), (DWORD)((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return ls;
}

static const wchar_t* kProviderName = L"Antiquarian's Cage phone sign-in";
static const std::wstring kCpRoot = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\";

// Requires administrator rights (run by install.ps1 via regsvr32). Registers only this provider; never touches others.
STDAPI DllRegisterServer() {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(g_module, path, MAX_PATH)) return HRESULT_FROM_WIN32(GetLastError());
    std::wstring clsid = ClsidString();
    std::wstring com = L"SOFTWARE\\Classes\\CLSID\\" + clsid;
    LSTATUS ls = SetDefault(HKEY_LOCAL_MACHINE, com, nullptr, kProviderName);
    if (!ls) ls = SetDefault(HKEY_LOCAL_MACHINE, com + L"\\InprocServer32", nullptr, path);
    if (!ls) ls = SetDefault(HKEY_LOCAL_MACHINE, com + L"\\InprocServer32", L"ThreadingModel", L"Apartment");
    if (!ls) ls = SetDefault(HKEY_LOCAL_MACHINE, kCpRoot + clsid, nullptr, kProviderName);
    return HRESULT_FROM_WIN32(ls);
}

STDAPI DllUnregisterServer() {
    std::wstring clsid = ClsidString();
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, (kCpRoot + clsid).c_str());
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, (L"SOFTWARE\\Classes\\CLSID\\" + clsid).c_str());
    return S_OK;
}
