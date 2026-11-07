// Antiquarian's Cage credential provider: "Sign in with your phone" tile for Windows logon and unlock.
#pragma once
#include "core.h"

#include <credentialprovider.h>
#include <atomic>

// {20C827DA-2D25-4842-B92D-57FB4924F87B}
static const CLSID CLSID_CageProvider = {0x20c827da, 0x2d25, 0x4842, {0xb9, 0x2d, 0x57, 0xfb, 0x49, 0x24, 0xf8, 0x7b}};

extern std::atomic<long> g_dllRefs;

enum FieldId : DWORD {
    FI_TITLE = 0,      // large text
    FI_NUMBER,         // large text: the number to tap on the phone
    FI_STATUS,         // small text: instructions / errors
    FI_USERNAME,       // edit
    FI_PASSWORD,       // password (first-time setup only)
    FI_SETUP_LINK,     // command link: toggle setup mode
    FI_SUBMIT,         // submit button
    FI_COUNT
};

class CageProvider;

class CageCredential : public ICredentialProviderCredential {
public:
    CageCredential(CageProvider* owner, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { long r = --refs_; if (!r) delete this; return r; }

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* autoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override;
    IFACEMETHODIMP GetStringValue(DWORD id, PWSTR* value) override;
    IFACEMETHODIMP GetBitmapValue(DWORD, HBITMAP*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD id, DWORD* adjacentTo) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD id, PCWSTR value) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD id) override;
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
                                    PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS substatus, PWSTR* statusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;

    bool IsReady() { EnterCriticalSection(&cs_); bool r = state_ == State::Ready; LeaveCriticalSection(&cs_); return r; }
    void Shutdown();

private:
    ~CageCredential();
    enum class State { Idle, Waiting, Ready };

    void SetField(DWORD id, const std::wstring& text);
    void ShowPassword(bool show);
    void Fail(const std::wstring& message);
    HRESULT Begin(std::wstring& statusOut);
    static DWORD WINAPI PollThread(LPVOID self);
    void Poll();

    std::atomic<long> refs_{1};
    CageProvider* owner_;  // not ref-counted: the provider owns this credential and outlives it
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_;
    CRITICAL_SECTION cs_;
    ICredentialProviderCredentialEvents* events_ = nullptr;

    State state_ = State::Idle;
    bool setupMode_ = false;
    std::atomic<bool> cancel_{false};
    HANDLE thread_ = nullptr;

    std::wstring strings_[FI_COUNT];
    std::wstring username_, domain_, user_, sid_;
    std::wstring password_;       // typed (setup) or unsealed (unlock); wiped after serialization
    cage::SecureBytes setupKey_;  // K during setup, wiped once stored
    cage::SecureBytes sealed_;    // password sealed under K during setup
    std::string requestId_;
};

class CageProvider : public ICredentialProvider {
public:
    CageProvider() { ++g_dllRefs; }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { long r = --refs_; if (!r) delete this; return r; }

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD flags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override { *count = FI_COUNT; return S_OK; }
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override;

    // Called by the credential's worker thread when it is ready to sign in.
    void CredentialReady();

private:
    ~CageProvider();
    std::atomic<long> refs_{1};
    CageCredential* credential_ = nullptr;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_ = CPUS_INVALID;
    ICredentialProviderEvents* events_ = nullptr;
    UINT_PTR adviseContext_ = 0;
    SRWLOCK lock_ = SRWLOCK_INIT;
};
