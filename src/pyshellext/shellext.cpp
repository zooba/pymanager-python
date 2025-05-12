#define _WIN32_WINNT _WIN32_WINNT_WIN10
#include <sdkddkver.h>

#define __WRL_CLASSIC_COM__
#include <wrl.h>

using namespace Microsoft::WRL;

#include "shellext.h"

static HINSTANCE hModule;

#define CLSID_IDLE_COMMAND "{C7E29CB0-9691-4DE8-B72B-6719DDC0B4A1}"
#define CLSID_LAUNCH_COMMAND "{F7209EE3-FC96-40F4-8C3F-4B7D3994370D}"
#define CLSID_COMMAND_ENUMERATOR "{F82C8CD5-A69C-45CC-ADC6-87FC5F4A7429}"
#define CLSID_PYTHON_DROP_TARGET "{576E91FB-BDF5-4E9C-9DE3-B4E9997F25FC}"


static HRESULT CoTaskCopyWstr(LPWSTR *dest, const std::wstring &src)
{
    if (!dest) {
        return E_POINTER;
    }
    *dest = (LPWSTR)CoTaskMemAlloc((src.size() + 1) * sizeof(WCHAR));
    if (!*dest) {
        return E_OUTOFMEMORY;
    }
    wcsncpy_s(*dest, src.size() + 1, src.data(), src.size());
    return S_OK;
}


LRESULT RegReadStr(HKEY key, LPCWSTR valueName, std::wstring& result)
{
    DWORD reg_type;
    while (true) {
        DWORD cch = result.size() * sizeof(result[0]);
        LRESULT err = RegQueryValueEx(key, valueName, NULL, &reg_type,
                                      (LPBYTE)result.data(), &cch);
        cch /= sizeof(result[0]);
        if (err == ERROR_SUCCESS && reg_type == REG_SZ) {
            result.resize(cch);
            while (!result.empty() && result.back() == L'\0') {
                result.pop_back();
            }
            return err;
        }
        if (err && err != ERROR_MORE_DATA) {
            return err;
        }
        if (reg_type != REG_SZ) {
            return ERROR_INVALID_DATA;
        }
        if (cch <= result.size()) {
            return err;
        }
        result.resize(cch);
    }
}


HRESULT ReadIdleInstalls(std::vector<IdleData> &idles, HKEY hkPython, LPCWSTR company, REGSAM flags)
{
    HKEY hkCompany = NULL, hkTag = NULL, hkInstall = NULL;
    LSTATUS err = RegOpenKeyExW(
        hkPython,
        company,
        0,
        KEY_READ | flags,
        &hkCompany
    );

    for (DWORD i = 0; !err && i < 64; ++i) {
        wchar_t name[512];
        DWORD cchName = sizeof(name) / sizeof(name[0]);
        err = RegEnumKeyExW(hkCompany, i, name, &cchName, NULL, NULL, NULL, NULL);
        if (!err) {
            err = RegOpenKeyExW(hkCompany, name, 0, KEY_READ | flags, &hkTag);
        }
        if (!err) {
            err = RegOpenKeyExW(hkTag, L"InstallPath", 0, KEY_READ | flags, &hkInstall);
        }
        if (err) {
            break;
        }

        IdleData data;

        err = RegReadStr(hkTag, L"DisplayName", data.title);
        if (err) {
            data.title = std::wstring(L"Python ") + name;
        }

        err = RegReadStr(hkInstall, L"WindowedExecutablePath", data.exe);
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_INVALID_DATA) {
            err = RegReadStr(hkInstall, L"ExecutablePath", data.exe);
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_INVALID_DATA) {
                err = RegReadStr(hkInstall, NULL, data.exe);
                if (!err) {
                    if (data.exe.back() != L'\\') {
                        data.exe += L"\\python.exe";
                    } else {
                        data.exe += L"python.exe";
                    }
                }
            }
        }
        if (err) {
            break;
        }

        err = RegReadStr(hkInstall, L"IdlePath", data.idle);
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_INVALID_DATA) {
            if (0 == wcsicmp(company, L"PythonCore")) {
                // Only use fallback logic for PythonCore
                err = RegReadStr(hkInstall, NULL, data.idle);
                if (!err) {
                    if (data.idle.back() != L'\\') {
                        data.idle += L"\\Lib\\idlelib\\idle.pyw";
                    } else {
                        data.idle += L"Lib\\idlelib\\idle.pyw";
                    }
                }
            } else {
                err = 0;
            }
        }
        if (err) {
            break;
        }

        RegCloseKey(hkInstall);
        hkInstall = NULL;
        RegCloseKey(hkTag);
        hkTag = NULL;

        if (!data.exe.empty()
            && !data.idle.empty()
            && GetFileAttributesW(data.exe.c_str()) != INVALID_FILE_ATTRIBUTES
            && GetFileAttributesW(data.idle.c_str()) != INVALID_FILE_ATTRIBUTES) {
            idles.push_back(data);
        }
    }
    if (hkInstall) {
        RegCloseKey(hkInstall);
    }
    if (hkTag) {
        RegCloseKey(hkTag);
    }
    if (hkCompany) {
        RegCloseKey(hkCompany);
    }
    if (err && err != ERROR_NO_MORE_ITEMS && err != ERROR_FILE_NOT_FOUND) {
        return HRESULT_FROM_WIN32(err);
    }
    return S_OK;
}

HRESULT ReadAllIdleInstalls(std::vector<IdleData> &idles, HKEY hive, LPCWSTR root, REGSAM flags)
{
    HKEY hkPython = NULL;
    HRESULT hr = S_OK;
    LSTATUS err = RegOpenKeyExW(hive, root ? root : L"", 0, KEY_READ | flags, &hkPython);

    for (DWORD i = 0; !err && hr == S_OK && i < 64; ++i) {
        wchar_t name[512];
        DWORD cchName = sizeof(name) / sizeof(name[0]);
        err = RegEnumKeyExW(hkPython, i, name, &cchName, NULL, NULL, NULL, NULL);
        if (!err) {
            hr = ReadIdleInstalls(idles, hkPython, name, flags);
        }
    }

    if (hkPython) {
        RegCloseKey(hkPython);
    }

    if (err && err != ERROR_NO_MORE_ITEMS && err != ERROR_FILE_NOT_FOUND) {
        return HRESULT_FROM_WIN32(err);
    }
    return hr;
}

class DECLSPEC_UUID(CLSID_LAUNCH_COMMAND) LaunchCommand
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IExplorerCommand, IObjectWithSite>
{
    std::wstring title;
    std::wstring exe;
    std::wstring idle;
public:
    LaunchCommand(const IdleData &data) : title(data.title), exe(data.exe), idle(data.idle)
    { }

    // IExplorerCommand
    IFACEMETHODIMP GetTitle(IShellItemArray *psiItemArray, LPWSTR *ppszName)
    {
        return CoTaskCopyWstr(ppszName, title);
    }

    IFACEMETHODIMP GetIcon(IShellItemArray *psiItemArray, LPWSTR *ppszIcon)
    {
        *ppszIcon = NULL;
        return E_NOTIMPL;
    }

    IFACEMETHODIMP GetToolTip(IShellItemArray *psiItemArray, LPWSTR *ppszInfotip)
    {
        *ppszInfotip = NULL;
        return E_NOTIMPL;
    }

    IFACEMETHODIMP GetCanonicalName(GUID* pguidCommandName)
    {
        *pguidCommandName = __uuidof(LaunchCommand);
        return S_OK;
    }

    IFACEMETHODIMP GetState(IShellItemArray *psiItemArray, BOOL fOkToBeSlow, EXPCMDSTATE *pCmdState)
    {
        *pCmdState = ECS_ENABLED;
        return S_OK;
    }

    IFACEMETHODIMP Invoke(IShellItemArray *psiItemArray, IBindCtx *pbc)
    {
        std::wstring parameters;
        if (idle.find(L' ') != idle.npos) {
            parameters = L"\"" + idle + L"\"";
        } else {
            parameters = idle;
        }

        HRESULT hr;
        DWORD count;
        psiItemArray->GetCount(&count);
        for (DWORD i = 0; i < count; ++i) {
            PWSTR path;
            IShellItem *psi;
            hr = psiItemArray->GetItemAt(0, &psi);
            if (FAILED(hr))
                continue;
            hr = psi->GetDisplayName(SIGDN_FILESYSPATH, &path);
            psi->Release();
            if (FAILED(hr))
                continue;

            if (wcschr(path, L' ')) {
                parameters += L" \"";
                parameters += path;
                parameters += L"\"";
            } else {
                parameters += L" ";
                parameters += path;
            }
            CoTaskMemFree(path);
        }

        SHELLEXECUTEINFOW sei = {
            sizeof(SHELLEXECUTEINFOW),
            SEE_MASK_NO_CONSOLE | SEE_MASK_NOASYNC,
            NULL,
            NULL,
            exe.c_str(),
            parameters.c_str(),
            NULL
        };
        OutputDebugStringW(L"IdleCommand::Invoke");
        OutputDebugStringW(exe.c_str());
        OutputDebugStringW(parameters.c_str());
        ShellExecuteExW(&sei);
        return S_OK;
    }

    IFACEMETHODIMP GetFlags(EXPCMDFLAGS *pFlags)
    {
        *pFlags = ECF_DEFAULT;
        return S_OK;
    }

    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand **ppEnum)
    {
        *ppEnum = NULL;
        return E_NOTIMPL;
    }

    // IObjectWithSite
private:
    ComPtr<IUnknown> _site;

public:
    IFACEMETHODIMP GetSite(REFIID riid, void **ppvSite)
    {
        if (_site) {
            return _site->QueryInterface(riid, ppvSite);
        }
        *ppvSite = NULL;
        return E_FAIL;
    }

    IFACEMETHODIMP SetSite(IUnknown *pSite)
    {
        _site = pSite;
        return S_OK;
    }
};


class DECLSPEC_UUID(CLSID_COMMAND_ENUMERATOR) CommandEnumerator
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IEnumExplorerCommand>
{
    std::vector<IdleData> idles;
    size_t index;
public:
    CommandEnumerator(std::vector<IdleData> idles, size_t index)
        : idles(idles), index(index) { }

    IFACEMETHODIMP Clone(IEnumExplorerCommand **ppenum)
    {
        return Make<CommandEnumerator>(idles, index)
            ->QueryInterface(IID_IEnumExplorerCommand, (void **)ppenum);
    }

    IFACEMETHODIMP Next(ULONG celt, IExplorerCommand **pUICommand, ULONG *pceltFetched)
    {
        ULONG c = 0;
        while (celt-- && index < idles.size()) {
            *pUICommand = Make<LaunchCommand>(idles[index]).Detach();
            index += 1;
            c += 1;
        }
        if (pceltFetched) {
            *pceltFetched = c;
        }
        return c ? S_OK : S_FALSE;
    }

    IFACEMETHODIMP Reset()
    {
        index = 0;
        return S_OK;
    }

    IFACEMETHODIMP Skip(ULONG celt)
    {
        index += celt;
        return S_OK;
    }
};


class DECLSPEC_UUID(CLSID_IDLE_COMMAND) IdleCommand
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IExplorerCommand, IObjectWithSite>
{
    std::vector<IdleData> idles;
    std::wstring iconPath;
    std::wstring title;
public:
    IdleCommand() : title(L"Edit in &IDLE")
    {
        HRESULT hr;

        DWORD cch = 260;
        while (iconPath.size() < cch) {
            iconPath.resize(cch);
            cch = GetModuleFileNameW(hModule, iconPath.data(), iconPath.size());
        }
        iconPath.resize(cch);
        if (cch) {
            iconPath += L",-4";
        }

        hr = ReadAllIdleInstalls(idles, HKEY_LOCAL_MACHINE, L"Software\\Python", KEY_WOW64_32KEY);
        if (SUCCEEDED(hr)) {
            hr = ReadAllIdleInstalls(idles, HKEY_LOCAL_MACHINE, L"Software\\Python", KEY_WOW64_64KEY);
        }
        if (SUCCEEDED(hr)) {
            hr = ReadAllIdleInstalls(idles, HKEY_CURRENT_USER, L"Software\\Python", 0);
        }

        if (FAILED(hr)) {
            wchar_t buffer[512];
            swprintf_s(buffer, L"IdleCommand error 0x%08X", (DWORD)hr);
            OutputDebugStringW(buffer);
            idles.clear();
        }
    }

    #ifdef PYSHELLEXT_TEST
    IdleCommand(HKEY hive, LPCWSTR root) : title(L"Edit in &IDLE")
    {
        HRESULT hr;

        DWORD cch = 260;
        while (iconPath.size() < cch) {
            iconPath.resize(cch);
            cch = GetModuleFileNameW(hModule, iconPath.data(), iconPath.size());
        }
        iconPath.resize(cch);
        if (cch) {
            iconPath += L",-4";
        }

        hr = ReadAllIdleInstalls(idles, hive, root, 0);

        if (FAILED(hr)) {
            idles.clear();
        }
    }
    #endif

    // IExplorerCommand
    IFACEMETHODIMP GetTitle(IShellItemArray *psiItemArray, LPWSTR *ppszName)
    {
        return CoTaskCopyWstr(ppszName, title);
    }

    IFACEMETHODIMP GetIcon(IShellItemArray *psiItemArray, LPWSTR *ppszIcon)
    {
        if (!iconPath.empty()) {
            return CoTaskCopyWstr(ppszIcon, iconPath);
        } else {
            *ppszIcon = NULL;
            return E_NOTIMPL;
        }
    }

    IFACEMETHODIMP GetToolTip(IShellItemArray *psiItemArray, LPWSTR *ppszInfotip)
    {
        *ppszInfotip = NULL;
        return E_NOTIMPL;
    }

    IFACEMETHODIMP GetCanonicalName(GUID* pguidCommandName)
    {
        *pguidCommandName = __uuidof(IdleCommand);
        return S_OK;
    }

    IFACEMETHODIMP GetState(IShellItemArray *psiItemArray, BOOL fOkToBeSlow, EXPCMDSTATE *pCmdState)
    {
        *pCmdState = idles.size() ? ECS_ENABLED : ECS_HIDDEN;
        return S_OK;
    }

    IFACEMETHODIMP Invoke(IShellItemArray *psiItemArray, IBindCtx *pbc)
    {
        return E_NOTIMPL;
    }

    IFACEMETHODIMP GetFlags(EXPCMDFLAGS *pFlags)
    {
        *pFlags = ECF_HASSUBCOMMANDS;
        return S_OK;
    }

    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand **ppEnum)
    {
        *ppEnum = Make<CommandEnumerator>(
            std::vector<IdleData>{std::rbegin(idles), std::rend(idles)},
            0
        ).Detach();
        return S_OK;
    }

    // IObjectWithSite
private:
    ComPtr<IUnknown> _site;

public:
    IFACEMETHODIMP GetSite(REFIID riid, void **ppvSite)
    {
        if (_site) {
            return _site->QueryInterface(riid, ppvSite);
        }
        *ppvSite = NULL;
        return E_FAIL;
    }

    IFACEMETHODIMP SetSite(IUnknown *pSite)
    {
        _site = pSite;
        return S_OK;
    }
};


class DECLSPEC_UUID(CLSID_PYTHON_DROP_TARGET) PythonDropTarget
    : public RuntimeClass<RuntimeClassFlags<ClassicCom>, IDropTarget, IObjectWithSite>
{

    std::wstring _scriptName;
    std::wstring _scriptDirectory;
    std::wstring _scriptPath;

public:
    // IDropTarget
    STDMETHODIMP DragEnter(IDataObject *pDataObj, DWORD grfKeyState, POINTL pt, DWORD *pdwEffect)
    {
        if (_scriptName.empty()) {
            *pdwEffect = DROPEFFECT_NONE;
            return S_OK;
        }

        *pdwEffect = DROPEFFECT_MOVE;

        HRESULT hr;
        static CLIPFORMAT cfDropDescription = RegisterClipboardFormat(CFSTR_DROPDESCRIPTION);
        static CLIPFORMAT cfDragWindow = RegisterClipboardFormat(L"DragWindow");
        static FORMATETC fmt1 = {cfDropDescription, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
        static FORMATETC fmt2 = {cfDragWindow, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
        STGMEDIUM medium;
        DROPDESCRIPTION *dd;
        HWND *pHWnd;

        hr = pDataObj->GetData(&fmt1, &medium);
        if (SUCCEEDED(hr)) {
            if (dd = (DROPDESCRIPTION*)GlobalLock(medium.hGlobal)) {
                wcscpy_s(dd->szMessage, L"Open with %1");
                wcscpy_s(dd->szInsert, _scriptName.c_str());
                dd->type = DROPIMAGE_MOVE;
                GlobalUnlock(medium.hGlobal);
            }
            ReleaseStgMedium(&medium);
        } else {
            OutputDebugStringW(L"PyShellExt::DragEnter - failed to update drop description");
            return hr;
        }

        hr = pDataObj->GetData(&fmt2, &medium);
        if (SUCCEEDED(hr)) {
            if ((pHWnd = (HWND*)GlobalLock(medium.hGlobal)) != NULL) {
                // #define DDWM_UPDATEWINDOW (WM_USER+3)
                SendMessage(*pHWnd, (WM_USER+3), 0, NULL);
                GlobalUnlock(medium.hGlobal);
            }
            ReleaseStgMedium(&medium);
        } else {
            OutputDebugStringW(L"PyShellExt::DragEnter - failed to notify drag window");
            return hr;
        }

        return S_OK;
    }

    STDMETHODIMP DragLeave()
    {
        return S_OK;
    }

    STDMETHODIMP DragOver(DWORD grfKeyState, POINTL pt, DWORD *pdwEffect)
    {
        return S_OK;
    }

    STDMETHODIMP Drop(IDataObject *pDataObj, DWORD grfKeyState, POINTL pt, DWORD *pdwEffect)
    {
        HRESULT hr;
        std::vector<std::wstring> files;
        std::wstring args;
        FORMATETC fmt = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
        STGMEDIUM medium;
        DROPFILES *pDropFiles = NULL;

        hr = pDataObj->GetData(&fmt, &medium);
        if (SUCCEEDED(hr)) {
            pDropFiles = (DROPFILES*)GlobalLock(medium.hGlobal);
        }
        if (!pDropFiles) {
            OutputDebugString(L"PyShellExt::GetArguments - failed to lock CF_HDROP hGlobal");
            ReleaseStgMedium(&medium);
            return E_FAIL;
        }

        if (pDropFiles->fWide) {
            LPCWSTR name = (LPCWSTR)((char*)pDropFiles + pDropFiles->pFiles);
            while (*name) {
                auto &n = files.emplace_back(name);
                name += n.size() + 1;
            }
        } else {
            LPCSTR name = (LPCSTR)((char*)pDropFiles + pDropFiles->pFiles);
            while (*name) {
                size_t wlen = MultiByteToWideChar(CP_ACP, 0, name, -1, NULL, 0);
                if (wlen) {
                    auto &n = files.emplace_back(wlen);
                    n.resize(MultiByteToWideChar(CP_ACP, 0, name, -1, n.data(), wlen));
                }
                name += strlen(name) + 1;
            }
        }

        for (const auto &n : files) {
            if (!args.empty()) {
                args.push_back(L' ');
            }
            if (n.find(L' ') == n.npos) {
                args += n;
            } else {
                args.push_back(L'"');
                args += n;
                if (args.back() == L'\\') {
                    args.push_back(L'\\');
                }
                args.push_back(L'"');
            }
        }

        *pdwEffect = DROPEFFECT_NONE;

        SHELLEXECUTEINFOW sei = {
            sizeof(SHELLEXECUTEINFOW),
            SEE_MASK_NOASYNC,
            NULL,
            NULL,
            _scriptPath.c_str(),
            args.c_str(),
            _scriptDirectory.c_str()
        };
        OutputDebugStringW(L"PythonDropTarget::Invoke");
        OutputDebugStringW(_scriptPath.c_str());
        OutputDebugStringW(args.c_str());
        OutputDebugStringW(_scriptDirectory.c_str());
        ShellExecuteExW(&sei);

        return S_OK;
    }

    // IPersistFile
    STDMETHODIMP GetCurFile(LPOLESTR *ppszFileName) {
        return CoTaskCopyWstr((LPWSTR*)ppszFileName, _scriptPath);
    }

    STDMETHODIMP IsDirty() {
        return S_FALSE;
    }

    STDMETHODIMP Load(LPCOLESTR pszFileName, DWORD dwMode) {
        if (pszFileName) {
            _scriptPath = pszFileName;
            _scriptName = PathFindFileNameW(pszFileName);
            _scriptDirectory = _scriptPath;
            _scriptDirectory.resize(_scriptDirectory.size() - _scriptName.size());
        } else {
            _scriptPath.clear();
            _scriptName.clear();
            _scriptDirectory.clear();
        }
        return S_OK;
    }

    STDMETHODIMP Save(LPCOLESTR pszFileName, BOOL fRemember) {
        return E_NOTIMPL;
    }

    STDMETHODIMP SaveCompleted(LPCOLESTR pszFileName) {
        return E_NOTIMPL;
    }

    STDMETHODIMP GetClassID(CLSID *pClassID) {
        *pClassID = __uuidof(PythonDropTarget);
        return S_OK;
    }

    // IObjectWithSite
private:
    ComPtr<IUnknown> _site;

public:
    IFACEMETHODIMP GetSite(REFIID riid, void **ppvSite)
    {
        if (_site) {
            return _site->QueryInterface(riid, ppvSite);
        }
        *ppvSite = NULL;
        return E_FAIL;
    }

    IFACEMETHODIMP SetSite(IUnknown *pSite)
    {
        _site = pSite;
        return S_OK;
    }
};


CoCreatableClass(IdleCommand);
CoCreatableClass(PythonDropTarget);

#ifdef PYSHELLEXT_TEST

IExplorerCommand *MakeLaunchCommand(std::wstring title, std::wstring exe, std::wstring idle)
{
    IdleData data = { .title = title, .exe = exe, .idle = idle };
    return Make<LaunchCommand>(data).Detach();
}


IExplorerCommand *MakeIdleCommand(HKEY hive, LPCWSTR root)
{
    return Make<IdleCommand>(hive, root).Detach();
}

#elif defined(_WINDLL)

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, _COM_Outptr_ void** ppv)
{
    return Module<InProc>::GetModule().GetClassObject(rclsid, riid, ppv);
}


STDAPI DllCanUnloadNow()
{
    return Module<InProc>::GetModule().Terminate() ? S_OK : S_FALSE;
}

STDAPI_(BOOL) DllMain(_In_opt_ HINSTANCE hinst, DWORD reason, _In_opt_ void*)
{
    if (reason == DLL_PROCESS_ATTACH) {
        hModule = hinst;
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}

#else

class OutOfProcModule : public Module<OutOfProc, OutOfProcModule>
{ };


int WINAPI wWinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPWSTR lpCmdLine,
    int nCmdShow
)
{
    HANDLE hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    hModule = hInstance;

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    auto& module = OutOfProcModule::Create([=]() { SetEvent(hStopEvent); });
    module.RegisterObjects();
    ::WaitForSingleObject(hStopEvent, INFINITE);
    module.UnregisterObjects();
    CoUninitialize();
    return 0;
}

#endif
