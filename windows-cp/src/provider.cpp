// Antiquarian's Cage credential provider - tile and credential logic. Design: documentation/12-windows-phone-unlock.md
//
// Safety properties:
//  * The provider only ADDS a tile. Windows' own password/PIN providers are untouched, so a failure here never
//    prevents signing in the normal way.
//  * Nothing is cached across sign-ins: the password is unsealed only after a phone approval and wiped right after
//    it has been handed to LogonUI.
//  * Every error is shown on the tile and written to %ProgramData%\AntiquariansCage\credential-provider.log
//    (never secrets).
#include "provider.h"

#include <shlwapi.h>
#include <new>

#pragma comment(lib, "shlwapi.lib")

using namespace cage;

static const wchar_t* kIdleStatus = L"Enter your Windows user name and press \x2192. Then approve on your phone.";

static const struct { DWORD id; CREDENTIAL_PROVIDER_FIELD_TYPE type; const wchar_t* label; } kFields[FI_COUNT] = {
    {FI_TITLE, CPFT_LARGE_TEXT, L"Sign in with your phone"},
    {FI_NUMBER, CPFT_LARGE_TEXT, L"Number"},
    {FI_STATUS, CPFT_SMALL_TEXT, L"Status"},
    {FI_USERNAME, CPFT_EDIT_TEXT, L"User name"},
    {FI_PASSWORD, CPFT_PASSWORD_TEXT, L"Windows password (one-time setup)"},
    {FI_SETUP_LINK, CPFT_COMMAND_LINK, L"First time on this PC? Set up phone sign-in"},
    {FI_SUBMIT, CPFT_SUBMIT_BUTTON, L"Submit"},
};

// =================================================================================================== credential
CageCredential::CageCredential(CageProvider* owner, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) : owner_(owner), cpus_(cpus) {
    InitializeCriticalSection(&cs_);
    ++g_dllRefs;
    for (DWORD i = 0; i < FI_COUNT; ++i) strings_[i] = kFields[i].label;
    strings_[FI_NUMBER] = L"";
    strings_[FI_STATUS] = kIdleStatus;
    strings_[FI_USERNAME] = L"";
    strings_[FI_PASSWORD] = L"";
}

CageCredential::~CageCredential() {
    Shutdown();
    WipeString(password_);
    WipeString(strings_[FI_PASSWORD]);
    if (events_) events_->Release();
    DeleteCriticalSection(&cs_);
    --g_dllRefs;
}

IFACEMETHODIMP CageCredential::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

void CageCredential::Shutdown() {
    cancel_ = true;
    HANDLE t = nullptr;
    EnterCriticalSection(&cs_);
    t = thread_;
    thread_ = nullptr;
    LeaveCriticalSection(&cs_);
    if (t) {
        WaitForSingleObject(t, 3000);  // the poller checks cancel_ every 250 ms
        CloseHandle(t);
    }
}

IFACEMETHODIMP CageCredential::Advise(ICredentialProviderCredentialEvents* events) {
    EnterCriticalSection(&cs_);
    if (events_) events_->Release();
    events_ = events;
    if (events_) events_->AddRef();
    LeaveCriticalSection(&cs_);
    return S_OK;
}

IFACEMETHODIMP CageCredential::UnAdvise() {
    EnterCriticalSection(&cs_);
    if (events_) events_->Release();
    events_ = nullptr;
    LeaveCriticalSection(&cs_);
    return S_OK;
}

IFACEMETHODIMP CageCredential::SetSelected(BOOL* autoLogon) {
    *autoLogon = IsReady();
    return S_OK;
}

IFACEMETHODIMP CageCredential::SetDeselected() {
    EnterCriticalSection(&cs_);
    bool waiting = state_ == State::Waiting;
    LeaveCriticalSection(&cs_);
    if (!waiting) {  // leaving the tile discards anything typed; a pending phone request keeps running
        WipeString(strings_[FI_PASSWORD]);
        SetField(FI_PASSWORD, L"");
    }
    return S_OK;
}

IFACEMETHODIMP CageCredential::GetFieldState(DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                                             CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) {
    if (id >= FI_COUNT || !state || !interactive) return E_INVALIDARG;
    *interactive = CPFIS_NONE;
    switch (id) {
        case FI_TITLE: *state = CPFS_DISPLAY_IN_BOTH; break;
        case FI_PASSWORD: *state = setupMode_ ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN; break;
        case FI_USERNAME: *state = CPFS_DISPLAY_IN_SELECTED_TILE; *interactive = CPFIS_FOCUSED; break;
        default: *state = CPFS_DISPLAY_IN_SELECTED_TILE; break;
    }
    return S_OK;
}

IFACEMETHODIMP CageCredential::GetStringValue(DWORD id, PWSTR* value) {
    if (id >= FI_COUNT || !value) return E_INVALIDARG;
    EnterCriticalSection(&cs_);
    HRESULT hr = SHStrDupW(strings_[id].c_str(), value);
    LeaveCriticalSection(&cs_);
    return hr;
}

IFACEMETHODIMP CageCredential::GetSubmitButtonValue(DWORD id, DWORD* adjacentTo) {
    if (id != FI_SUBMIT || !adjacentTo) return E_INVALIDARG;
    *adjacentTo = FI_USERNAME;
    return S_OK;
}

IFACEMETHODIMP CageCredential::SetStringValue(DWORD id, PCWSTR value) {
    if (id != FI_USERNAME && id != FI_PASSWORD) return E_INVALIDARG;
    EnterCriticalSection(&cs_);
    if (id == FI_PASSWORD) WipeString(strings_[id]);
    strings_[id] = value ? value : L"";
    LeaveCriticalSection(&cs_);
    return S_OK;
}

void CageCredential::SetField(DWORD id, const std::wstring& text) {
    ICredentialProviderCredentialEvents* ev = nullptr;
    EnterCriticalSection(&cs_);
    strings_[id] = text;
    ev = events_;
    if (ev) ev->AddRef();
    LeaveCriticalSection(&cs_);
    if (ev) {
        ev->SetFieldString(this, id, text.c_str());
        ev->Release();
    }
}

void CageCredential::ShowPassword(bool show) {
    ICredentialProviderCredentialEvents* ev = nullptr;
    EnterCriticalSection(&cs_);
    ev = events_;
    if (ev) ev->AddRef();
    LeaveCriticalSection(&cs_);
    if (ev) {
        ev->SetFieldState(this, FI_PASSWORD, show ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
        ev->Release();
    }
}

IFACEMETHODIMP CageCredential::CommandLinkClicked(DWORD id) {
    if (id != FI_SETUP_LINK) return E_INVALIDARG;
    EnterCriticalSection(&cs_);
    bool busy = state_ != State::Idle;
    if (!busy) setupMode_ = !setupMode_;
    bool setup = setupMode_;
    LeaveCriticalSection(&cs_);
    if (busy) return S_OK;
    ShowPassword(setup);
    SetField(FI_SETUP_LINK, setup ? L"Cancel setup" : kFields[FI_SETUP_LINK].label);
    SetField(FI_STATUS, setup
        ? L"Setup: enter your user name and current Windows password, press \x2192, then approve on your phone. "
          L"The password is stored encrypted on this PC and can only be unlocked after a phone approval."
        : kIdleStatus);
    return S_OK;
}

void CageCredential::Fail(const std::wstring& message) {
    EnterCriticalSection(&cs_);
    state_ = State::Idle;
    WipeString(password_);
    setupKey_.wipe();
    sealed_.wipe();
    requestId_.clear();
    LeaveCriticalSection(&cs_);
    SetField(FI_NUMBER, L"");
    SetField(FI_STATUS, message);
    Log(L"failed: %s", message.c_str());
}

// Starts a phone request. Runs on the LogonUI thread inside GetSerialization; network work happens in the relay.
HRESULT CageCredential::Begin(std::wstring& status) {
    EnterCriticalSection(&cs_);
    username_ = strings_[FI_USERNAME];
    bool setup = setupMode_;
    if (setup) { WipeString(password_); password_ = strings_[FI_PASSWORD]; WipeString(strings_[FI_PASSWORD]); }
    LeaveCriticalSection(&cs_);
    SetField(FI_PASSWORD, L"");

    if (username_.empty()) { status = L"Enter your Windows user name first."; return E_INVALIDARG; }
    SplitUser(username_, domain_, user_);
    if (FAILED(LookupSid(domain_, user_, sid_))) { status = L"No Windows account with that name on this PC."; return E_INVALIDARG; }
    std::string account = ToUtf8(domain_ + L"\\" + user_);

    std::string request;
    if (setup) {
        if (password_.empty()) { status = L"Enter your current Windows password to set up phone sign-in."; return E_INVALIDARG; }
        if (FAILED(VerifyPassword(domain_, user_, password_))) {
            WipeString(password_);
            status = L"That password was not accepted by Windows.";
            return E_ACCESSDENIED;
        }
        setupKey_ = SecureBytes(32);
        HRESULT hr = RandomBytes(setupKey_.data.data(), 32);
        if (SUCCEEDED(hr)) hr = SealPassword(setupKey_, password_, sid_, sealed_);
        if (FAILED(hr)) { status = L"Could not encrypt the password on this PC."; return hr; }
        std::string k = Base64Encode(setupKey_.data.data(), 32);
        request = "{\"op\":\"start\",\"kind\":\"enroll\",\"windows_user\":\"" + JsonEscape(account) + "\",\"sid\":\"" +
                  JsonEscape(ToUtf8(sid_)) + "\",\"key\":\"" + k + "\"}";
        SecureZeroMemory(&k[0], k.size());
    } else {
        if (FAILED(Store{}.Load(sid_, sealed_))) {
            status = L"Phone sign-in is not set up for this account on this PC. Choose \x201C" L"First time on this PC?\x201D.";
            return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        }
        request = "{\"op\":\"start\",\"kind\":\"unlock\",\"windows_user\":\"" + JsonEscape(account) + "\",\"sid\":\"" +
                  JsonEscape(ToUtf8(sid_)) + "\"}";
    }
    RelayReply reply;
    HRESULT hr = RelayCall(request, reply);
    SecureZeroMemory(&request[0], request.size());
    if (FAILED(hr)) {
        status = L"The Antiquarian's Cage agent is not running on this PC. Use your password instead.";
        Log(L"relay unreachable: 0x%08lx", hr);
        return hr;
    }
    if (!reply.ok) {
        status = FromUtf8(reply.message.empty() ? reply.code : reply.message);
        return E_FAIL;
    }
    long long number = 0;
    std::string approverEmail;
    JsonGetString(reply.raw, "request_id", requestId_);
    JsonGetInt(reply.raw, "number", number);
    JsonGetString(reply.raw, "approver", approverEmail);
    wchar_t num[16];
    swprintf_s(num, L"%02lld", number);
    SetField(FI_NUMBER, num);
    status = std::wstring(L"On your phone (") + FromUtf8(approverEmail) + L"), open Cage Authenticator, tap " + num +
             L" and confirm with your fingerprint or face.";
    SetField(FI_STATUS, status);
    Log(L"%s request %hs started for %s", setup ? L"setup" : L"unlock", requestId_.c_str(), username_.c_str());

    EnterCriticalSection(&cs_);
    state_ = State::Waiting;
    cancel_ = false;
    AddRef();  // released by the poller
    thread_ = CreateThread(nullptr, 0, PollThread, this, 0, nullptr);
    if (!thread_) { state_ = State::Idle; LeaveCriticalSection(&cs_); Release(); status = L"Internal error."; return E_FAIL; }
    LeaveCriticalSection(&cs_);
    return S_OK;
}

DWORD WINAPI CageCredential::PollThread(LPVOID p) {
    auto* self = static_cast<CageCredential*>(p);
    self->Poll();
    // Whoever takes thread_ under the lock owns the handle; this way the final Release() below can never make the
    // destructor wait on the thread that is running it.
    EnterCriticalSection(&self->cs_);
    HANDLE h = self->thread_;
    self->thread_ = nullptr;
    LeaveCriticalSection(&self->cs_);
    if (h) CloseHandle(h);
    self->Release();
    return 0;
}

void CageCredential::Poll() {
    const ULONGLONG deadline = GetTickCount64() + 130000;
    while (!cancel_ && GetTickCount64() < deadline) {
        for (int i = 0; i < 8 && !cancel_; ++i) Sleep(250);
        if (cancel_) return;
        RelayReply reply;
        std::string req = "{\"op\":\"status\",\"request_id\":\"" + JsonEscape(requestId_) + "\"}";
        if (FAILED(RelayCall(req, reply))) { Fail(L"Lost contact with the Antiquarian's Cage agent. Use your password."); return; }
        if (!reply.ok) { Fail(FromUtf8(reply.message.empty() ? reply.code : reply.message)); return; }
        std::string st;
        JsonGetString(reply.raw, "status", st);
        if (st == "pending") continue;
        if (st == "denied") { Fail(L"The request was declined on your phone."); return; }
        if (st == "expired" || st == "consumed") { Fail(L"No approval arrived in time. Press \x2192 to try again."); return; }
        if (st == "enrolled") {
            HRESULT hr = Store{}.Save(sid_, sealed_);
            setupKey_.wipe();
            if (FAILED(hr)) { Log(L"store save failed 0x%08lx", hr); Fail(L"Approved, but the encrypted password could not be saved on this PC."); return; }
            Log(L"setup completed for %s", username_.c_str());
            SetField(FI_STATUS, L"Phone sign-in is set up. Signing you in\x2026");
        } else if (st == "approved") {
            std::string k;
            SecureBytes key;
            JsonGetString(reply.raw, "key", k);
            SecureZeroMemory(&reply.raw[0], reply.raw.size());
            bool decoded = Base64Decode(k, key);
            if (!k.empty()) SecureZeroMemory(&k[0], k.size());
            std::wstring pw;
            if (!decoded || FAILED(OpenPassword(key, sealed_, sid_, pw))) {
                Fail(L"Approved, but the saved password could not be decrypted. Set up phone sign-in again.");
                return;
            }
            EnterCriticalSection(&cs_);
            WipeString(password_);
            password_.swap(pw);
            LeaveCriticalSection(&cs_);
            Log(L"unlock approved for %s", username_.c_str());
            SetField(FI_STATUS, L"Verified on your phone. Signing you in\x2026");
        } else {
            Fail(L"Unexpected reply from the agent.");
            return;
        }
        EnterCriticalSection(&cs_);
        state_ = State::Ready;
        LeaveCriticalSection(&cs_);
        SetField(FI_NUMBER, L"\x2713");
        owner_->CredentialReady();  // LogonUI re-queries and calls GetSerialization (auto-logon)
        return;
    }
    if (!cancel_) Fail(L"No approval arrived in time. Press \x2192 to try again.");
}

IFACEMETHODIMP CageCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                                CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* cs,
                                                PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* icon) {
    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *statusText = nullptr;
    *icon = CPSI_NONE;
    ZeroMemory(cs, sizeof(*cs));

    EnterCriticalSection(&cs_);
    State st = state_;
    LeaveCriticalSection(&cs_);

    if (st == State::Waiting) {
        SHStrDupW(L"Still waiting for approval on your phone.", statusText);
        *icon = CPSI_WARNING;
        return S_OK;
    }
    if (st == State::Idle) {
        std::wstring status;
        HRESULT hr = Begin(status);
        if (FAILED(hr)) {
            Fail(status);
            SHStrDupW(status.c_str(), statusText);
            *icon = CPSI_ERROR;
        }
        return S_OK;  // never fail the call: the tile shows the error and other providers keep working
    }
    // Ready: hand the credential to LogonUI exactly once.
    ULONG pkg = 0;
    BYTE* buf = nullptr;
    DWORD size = 0;
    EnterCriticalSection(&cs_);
    HRESULT hr = NegotiatePackage(&pkg);
    if (SUCCEEDED(hr)) hr = PackInteractiveLogon(domain_, user_, password_, cpus_ == CPUS_UNLOCK_WORKSTATION, &buf, &size);
    WipeString(password_);
    state_ = State::Idle;
    LeaveCriticalSection(&cs_);
    if (FAILED(hr)) {
        Fail(L"Could not prepare the sign-in. Use your password.");
        return S_OK;
    }
    cs->ulAuthenticationPackage = pkg;
    cs->clsidCredentialProvider = CLSID_CageProvider;
    cs->rgbSerialization = buf;  // LogonUI frees and wipes it
    cs->cbSerialization = size;
    *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

IFACEMETHODIMP CageCredential::ReportResult(NTSTATUS status, NTSTATUS substatus, PWSTR* statusText,
                                            CREDENTIAL_PROVIDER_STATUS_ICON* icon) {
    *statusText = nullptr;
    *icon = CPSI_NONE;
    if (status == STATUS_SUCCESS) {
        Log(L"Windows accepted the sign-in for %s", username_.c_str());
        SetField(FI_NUMBER, L"");
        SetField(FI_STATUS, kIdleStatus);
        return S_OK;
    }
    Log(L"Windows rejected the sign-in: 0x%08lx / 0x%08lx", (unsigned long)status, (unsigned long)substatus);
    std::wstring msg = L"Windows did not accept the sign-in.";
    if (status == STATUS_LOGON_FAILURE || substatus == STATUS_WRONG_PASSWORD) {
        // The stored password is out of date (changed elsewhere): remove it so it is never retried.
        Store{}.Remove(sid_);
        msg = L"Your Windows password has changed. Sign in with your password once, then set up phone sign-in again.";
    }
    SetField(FI_NUMBER, L"");
    SetField(FI_STATUS, msg);
    SHStrDupW(msg.c_str(), statusText);
    *icon = CPSI_ERROR;
    return S_OK;
}

// =================================================================================================== provider
CageProvider::~CageProvider() {
    if (credential_) { credential_->Shutdown(); credential_->Release(); }
    if (events_) events_->Release();
    --g_dllRefs;
}

IFACEMETHODIMP CageProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP CageProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD) {
    if (cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION) return E_NOTIMPL;  // not in UAC, change password, CredUI
    cpus_ = cpus;
    if (!credential_) credential_ = new (std::nothrow) CageCredential(this, cpus);
    return credential_ ? S_OK : E_OUTOFMEMORY;
}

IFACEMETHODIMP CageProvider::Advise(ICredentialProviderEvents* events, UINT_PTR context) {
    AcquireSRWLockExclusive(&lock_);
    if (events_) events_->Release();
    events_ = events;
    if (events_) events_->AddRef();
    adviseContext_ = context;
    ReleaseSRWLockExclusive(&lock_);
    return S_OK;
}

IFACEMETHODIMP CageProvider::UnAdvise() {
    AcquireSRWLockExclusive(&lock_);
    if (events_) events_->Release();
    events_ = nullptr;
    ReleaseSRWLockExclusive(&lock_);
    return S_OK;
}

void CageProvider::CredentialReady() {
    AcquireSRWLockShared(&lock_);
    ICredentialProviderEvents* ev = events_;
    UINT_PTR ctx = adviseContext_;
    if (ev) ev->AddRef();
    ReleaseSRWLockShared(&lock_);
    if (ev) { ev->CredentialsChanged(ctx); ev->Release(); }
}

IFACEMETHODIMP CageProvider::GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) {
    if (index >= FI_COUNT || !out) return E_INVALIDARG;
    auto* d = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!d) return E_OUTOFMEMORY;
    ZeroMemory(d, sizeof(*d));
    d->dwFieldID = kFields[index].id;
    d->cpft = kFields[index].type;
    HRESULT hr = SHStrDupW(kFields[index].label, &d->pszLabel);
    if (FAILED(hr)) { CoTaskMemFree(d); return hr; }
    *out = d;
    return S_OK;
}

IFACEMETHODIMP CageProvider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon) {
    *count = credential_ ? 1 : 0;
    *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *autoLogon = FALSE;
    if (credential_ && credential_->IsReady()) {  // phone approved: sign in without another click
        *defaultIndex = 0;
        *autoLogon = TRUE;
    }
    return S_OK;
}

IFACEMETHODIMP CageProvider::GetCredentialAt(DWORD index, ICredentialProviderCredential** out) {
    if (index != 0 || !credential_ || !out) return E_INVALIDARG;
    return credential_->QueryInterface(IID_ICredentialProviderCredential, (void**)out);
}
