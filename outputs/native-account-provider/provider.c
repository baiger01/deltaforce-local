/* Partial owner-controlled local identity provider. Unknown interfaces stop
 * with explicit diagnostics. No original SDK, licensing result, or ticket is
 * forwarded/fabricated. This is not a complete game-compatible SDK.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>

typedef void (*VFn)(void);
typedef struct { uint64_t id; } NativeID;
typedef struct { VFn *vtable; } Object;
typedef struct { VFn *vtable; char *data; uint64_t count; uint64_t capacity; } NativeString;
typedef struct { VFn *vtable; NativeString *data; uint64_t count, capacity; } NativeStringArray;
typedef struct ZoneHandle { VFn *vtable; struct ZoneHandle *next; uint64_t zone_id; } ZoneHandle;
typedef struct { uint64_t id; uint32_t expires; char name[257]; } Identity;
typedef struct {
    uint32_t error_code, padding;
    NativeString error_msg, open_id, token;
    uint32_t token_expire_time, channel_id;
    NativeString channel, pf, user_name;
    uint8_t real_name_auth, padding2[7];
    NativeString pf_key, picture_url, ext_str, register_channel_id;
} NativeAccountInfo;
typedef struct {
    VFn *vtable;
    uint64_t rail_id, game_id;
    NativeString user_data;
    uint32_t result, padding;
} EventBase;
typedef struct { uint32_t id; void *listener; uint64_t generation; } Registration;
typedef struct PendingEvent { struct PendingEvent *next; EventBase data; NativeAccountInfo account_info; uint32_t event_id; } PendingEvent;
_Static_assert(sizeof(VFn) == 8 && sizeof(NativeID) == 8, "Windows x64 ABI");
_Static_assert(sizeof(NativeString) == 32 && offsetof(NativeString, data) == 8, "Recovered string ABI");
_Static_assert(sizeof(NativeStringArray) == 32 && offsetof(NativeStringArray, count) == 16, "Recovered string array ABI");
_Static_assert(sizeof(NativeAccountInfo) == 344 && offsetof(NativeAccountInfo, token) == 72 &&
    offsetof(NativeAccountInfo, token_expire_time) == 104 && offsetof(NativeAccountInfo, channel) == 112 &&
    offsetof(NativeAccountInfo, user_name) == 176 && offsetof(NativeAccountInfo, real_name_auth) == 208 &&
    offsetof(NativeAccountInfo, register_channel_id) == 312, "Recovered account structure ABI");
_Static_assert(sizeof(EventBase) == 64 && offsetof(EventBase, user_data) == 24 &&
    offsetof(EventBase, result) == 56, "Recovered DLC readiness event ABI");
_Static_assert(offsetof(PendingEvent, account_info) - offsetof(PendingEvent, data) == 64 &&
    sizeof(EventBase) + sizeof(NativeAccountInfo) == 408, "Recovered local login event ABI");
static HMODULE self_module;
static SRWLOCK state_lock = SRWLOCK_INIT;
static SRWLOCK logger_lock = SRWLOCK_INIT;
static SRWLOCK event_lock = SRWLOCK_INIT;
static INIT_ONCE tables_once = INIT_ONCE_STATIC_INIT;
static Identity identity;
static bool authorized, initialized;
static INTERNET_PORT service_port;
static char session_token[129];
static HANDLE stop_event, worker_thread;
static VFn factory_table[36], player_table[24], game_table[21], dlc_table[14], system_table[3], expansion_table[8], zone_helper_table[4], zone_server_table[15];
static Object factory = {factory_table}, player = {player_table}, game = {game_table}, dlc = {dlc_table};
static Object local_system = {system_table};
static Object expansion = {expansion_table};
static Object zone_helper = {zone_helper_table};
static VFn local_account_table[10];
static Object local_account = {local_account_table};
static ZoneHandle *zone_handles;
static unsigned zone_handle_count;
static VFn *client_string_table;
static volatile LONG sequence, pump_count;
static volatile LONG pumping;
static Registration registrations[128];
static uint64_t registration_generation;
static PendingEvent *pending_head, *pending_tail;
static unsigned pending_count;
static VFn ready_event_table[2], expansion_event_table[2], account_event_table[2];

#define LOCAL_CATALOG_READY_EVENT 17006u
#define LOCAL_EXPANSION_LIST_EVENT 32001u
#define LOCAL_ACCOUNT_LOGIN_EVENT 30001u
#define LOCAL_ACCOUNT_CHANNEL_ID 10000u
#define LOCAL_CLIENT_ACCOUNT_TYPE 1u
#define LOCAL_CLIENT_CHANNEL_NAME "QQ"
#define REQUEST_NOT_ACCEPTED 0xffffffffu

#define SET_SLOT(table,index,fn) do { \
    __typeof__(&fn) pointer = &fn; \
    _Static_assert(sizeof pointer == sizeof (table)[index], "Vtable function pointer size"); \
    memcpy(&(table)[index], &pointer, sizeof pointer); \
} while (0)

static uint64_t unix_time(void) {
    FILETIME value;
    GetSystemTimeAsFileTime(&value);
    uint64_t ticks = ((uint64_t)value.dwHighDateTime << 32) | value.dwLowDateTime;
    return ticks / 10000000u - 11644473600ull;
}

static bool adjacent_path(const WCHAR *name, WCHAR *path) {
    DWORD n = GetModuleFileNameW(self_module, path, 2048);
    if (!n || n >= 2048) return false;
    while (n && path[n - 1] != L'\\' && path[n - 1] != L'/') --n;
    size_t length = wcslen(name);
    if (!n || n + length >= 2048) return false;
    memcpy(path + n, name, (length + 1) * sizeof(WCHAR));
    return true;
}

static DWORD read_adjacent(const WCHAR *name, char *buffer, DWORD capacity) {
    WCHAR path[2048];
    if (!adjacent_path(name, path)) return 0;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    DWORD read = 0;
    BOOL okay = ReadFile(file, buffer, capacity, &read, NULL);
    CloseHandle(file);
    return okay && read < capacity ? read : 0;
}

static char *append(char *out, const char *s) { while (*s) *out++ = *s++; return out; }
static char *decimal(char *out, uint64_t n) {
    char digits[21]; unsigned count = 0;
    do { digits[count++] = (char)('0' + n % 10); n /= 10; } while (n);
    while (count) *out++ = digits[--count];
    return out;
}

static void record(const char *event, int result) {
    DWORD saved_error = GetLastError();
    WCHAR path[2048];
    DWORD length = GetEnvironmentVariableW(L"DF_SDK_OBSERVER_LOG", path, 2048);
    if (!length) {
        char encoded[6144];
        length = read_adjacent(L"df_sdk_observer_logpath.txt", encoded, sizeof encoded);
        while (length && (encoded[length - 1] == '\n' || encoded[length - 1] == '\r')) --length;
        if (!length || memchr(encoded, 0, length)) { SetLastError(saved_error); return; }
        int wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, encoded, (int)length, path, 2047);
        if (!wide_length) { SetLastError(saved_error); return; }
        path[wide_length] = 0;
    } else if (length >= 2048) { SetLastError(saved_error); return; }
    char buffer[640], *out = append(buffer, "{\"schema\":1,\"pid\":");
    out = decimal(out, GetCurrentProcessId());
    out = append(out, ",\"sequence\":");
    AcquireSRWLockExclusive(&logger_lock);
    out = decimal(out, (uint32_t)InterlockedIncrement(&sequence));
    out = append(out, ",\"event\":\""); out = append(out, event);
    out = append(out, "\",\"result\":");
    out = append(out, result < 0 ? "null" : result ? "true" : "false");
    out = append(out, "}\n");
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(file, buffer, (DWORD)(out - buffer), &written, NULL);
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&logger_lock);
    SetLastError(saved_error);
}

static void record_client_location(const char *role, const void *address) {
    /* Observe only the caller/callback already supplied to this provider.
     * Resolve its registered module through Windows; never read foreign code,
     * patch a callback, record an absolute pointer, or dump application state.
     */
    DWORD saved_error = GetLastError();
    HMODULE module = NULL;
    WCHAR path[2048];
    const char *tag = NULL;
    if (address && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)address, &module)) {
        DWORD length = GetModuleFileNameW(module, path, 2048);
        if (length && length < 2048) {
            const WCHAR *name = wcsrchr(path, L'\\');
            name = name ? name + 1 : path;
            if (!_wcsicmp(name, L"DeltaForceClient-Win64-Shipping.exe")) tag = "shipping";
            else if (!_wcsicmp(name, L"DeltaForceClient-Win64-ShippingBase.dll")) tag = "base";
        }
    }
    char event[160], *out = append(event, "sdk_trace_");
    out = append(out, role);
    if (tag && (uintptr_t)address >= (uintptr_t)module &&
            (uintptr_t)address - (uintptr_t)module <= UINT32_MAX) {
        out = append(out, "_"); out = append(out, tag);
        out = append(out, "_rva_");
        out = decimal(out, (uintptr_t)address - (uintptr_t)module);
        *out = 0; record(event, true);
    } else {
        out = append(out, "_unresolved"); *out = 0; record(event, false);
    }
    SetLastError(saved_error);
}

static volatile LONG diagnostic_code_mask;
static void capture_known_client_code(const void *supplied, unsigned kind) {
    /* Optional, fixed-version diagnostics on a callback already supplied by
     * the application. Capture only known login-related code ranges, never a full
     * process, credentials, heap state, an arbitrary address, or a code patch.
     * The test harness separately requires the immutable client SHA-256.
     */
    static const uint32_t supplied_rvas[] = {20221350u, 20224736u, 20224736u, 20224736u, 20224736u};
    static const uint32_t begin_rvas[] = {20221051u, 20224736u, 20224736u, 20225200u, 20192112u};
    /* Six chained RUNTIME_FUNCTION entries cover the result handler through
     * RVA 20227802. The first 117-byte entry alone was only its prologue. */
    static const uint32_t sizes[] = {781u, 463u, 463u, 2602u, 2963u};
    static const WCHAR *names[] = {L"account-type-caller.dfcode", L"login-callback-before.dfcode", L"login-callback-after.dfcode", L"login-result-handler.dfcode", L"login-info-conversion.dfcode"};
    if (kind >= 5 || !supplied) return;
    DWORD saved_error = GetLastError();
    WCHAR output[2048], module_path[2048];
    DWORD length = GetEnvironmentVariableW(L"DF_LOCAL_CODE_TRACE_DIR", output, 2048);
    HMODULE module = NULL;
    if (!length || length > 1800 ||
            !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)supplied, &module) ||
            (uintptr_t)supplied - (uintptr_t)module != supplied_rvas[kind]) goto done;
    DWORD path_length = GetModuleFileNameW(module, module_path, 2048);
    if (!path_length || path_length >= 2048) goto done;
    const WCHAR *name = wcsrchr(module_path, L'\\');
    if (!name || _wcsicmp(name + 1, L"DeltaForceClient-Win64-Shipping.exe")) goto done;
    const BYTE *begin = (const BYTE *)module + begin_rvas[kind];
    MEMORY_BASIC_INFORMATION region;
    if (!VirtualQuery(begin, &region, sizeof region) || region.State != MEM_COMMIT ||
            region.Type != MEM_IMAGE || region.AllocationBase != module ||
            (region.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
            !(region.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ||
            (uintptr_t)begin + sizes[kind] > (uintptr_t)region.BaseAddress + region.RegionSize) goto done;
    LONG bit = 1L << kind;
    if (InterlockedOr(&diagnostic_code_mask, bit) & bit) goto done;
    BYTE bytes[3200]; SIZE_T copied = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), begin, bytes, sizes[kind], &copied) || copied != sizes[kind]) goto done;
    if (output[length - 1] != L'\\' && output[length - 1] != L'/') output[length++] = L'\\';
    wcscpy(output + length, names[kind]);
    HANDLE file = CreateFileW(output, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        /* Header is private analysis metadata. Release archives exclude samples. */
        uint64_t header[] = {0x0000000145444344ull, begin_rvas[kind], sizes[kind], (uintptr_t)module};
        DWORD written = 0;
        bool ok = WriteFile(file, header, sizeof header, &written, NULL) && written == sizeof header;
        if (ok) ok = WriteFile(file, bytes, sizes[kind], &written, NULL) && written == sizes[kind];
        CloseHandle(file);
        record(kind == 0 ? "sdk_trace_account_type_code_captured" :
            kind == 1 ? "sdk_trace_login_callback_code_captured_before" :
            kind == 2 ? "sdk_trace_login_callback_code_captured_after" :
            kind == 3 ? "sdk_trace_login_result_handler_code_captured" : "sdk_trace_login_conversion_code_captured", ok);
    }
    SecureZeroMemory(bytes, sizeof bytes);
done:
    SetLastError(saved_error);
}

__declspec(noreturn) void DFLocalUnsupportedExport(const char *name) {
    record(name, false);
    ExitProcess(ERROR_CALL_NOT_IMPLEMENTED);
}

static bool valid_token(const char *token) {
    if (!token) return false;
    size_t n = 0;
    for (; token[n] && n < 128; ++n) {
        char c = token[n];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    }
    return n && n < 128 && token[n] == 0;
}

static bool fetch_identity(INTERNET_PORT port, const char *token, Identity *answer) {
    if (!port || !valid_token(token)) return false;
    HINTERNET http = NULL, connection = NULL, request = NULL;
    bool okay = false;
    http = WinHttpOpen(L"DFLocalIdentity/1", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!http || !WinHttpSetTimeouts(http, 2000, 2000, 2000, 2000)) goto finish;
    connection = WinHttpConnect(http, L"127.0.0.1", port, 0);
    if (!connection) goto finish;
    request = WinHttpOpenRequest(connection, L"POST", L"/api/local/native-identity", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) goto finish;
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof policy)) goto finish;
    WCHAR headers[256];
    const WCHAR prefix[] = L"Content-Type: application/json\r\nAuthorization: Bearer ";
    memcpy(headers, prefix, sizeof prefix);
    size_t position = (sizeof prefix / sizeof prefix[0]) - 1;
    for (size_t i = 0; token[i]; ++i) headers[position++] = (WCHAR)(unsigned char)token[i];
    headers[position++] = L'\r'; headers[position++] = L'\n'; headers[position] = 0;
    char body[] = "{}";
    if (!WinHttpSendRequest(request, headers, (DWORD)-1, body, 2, 2, 0) ||
        !WinHttpReceiveResponse(request, NULL)) goto finish;
    DWORD status = 0, bytes = sizeof status;
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &bytes, WINHTTP_NO_HEADER_INDEX) || status != 200) goto finish;
    WCHAR type[96]; bytes = sizeof type;
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
        type, &bytes, WINHTTP_NO_HEADER_INDEX) || wcscmp(type, L"application/vnd.df-local.identity")) goto finish;
    DWORD content_length = 0; bytes = sizeof content_length;
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &content_length, &bytes, WINHTTP_NO_HEADER_INDEX) ||
        content_length < 25 || content_length > 280) goto finish;
    unsigned char payload[281]; DWORD total = 0;
    while (total < sizeof payload) {
        DWORD read = 0;
        if (!WinHttpReadData(request, payload + total, (DWORD)sizeof payload - total, &read)) goto finish;
        if (!read) break;
        total += read;
    }
    if (total != content_length || total > 280 || memcmp(payload, "DFID", 4)) goto finish;
    uint16_t version, header_size;
    uint64_t id;
    uint32_t expires, name_length;
    memcpy(&version, payload + 4, 2); memcpy(&header_size, payload + 6, 2);
    memcpy(&id, payload + 8, 8); memcpy(&expires, payload + 16, 4); memcpy(&name_length, payload + 20, 4);
    if (version != 1 || header_size != 24 || !id || id >= (1ull << 63) ||
        expires <= unix_time() || expires > unix_time() + 86500 ||
        !name_length || name_length > 256 || total != 24 + name_length || memchr(payload + 24, 0, name_length)) goto finish;
    WCHAR unicode[257];
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (char *)payload + 24, (int)name_length, unicode, 256)) goto finish;
    answer->id = id; answer->expires = expires;
    memcpy(answer->name, payload + 24, name_length); answer->name[name_length] = 0;
    okay = true;
finish:
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    if (http) WinHttpCloseHandle(http);
    return okay;
}

bool DFLocalAuthorize(uint16_t port, const char *token) {
    Identity fresh = {0};
    bool okay = fetch_identity(port, token, &fresh);
    AcquireSRWLockExclusive(&state_lock);
    authorized = okay;
    identity = fresh;
    service_port = okay ? port : 0;
    SecureZeroMemory(session_token, sizeof session_token);
    if (okay) memcpy(session_token, token, strlen(token) + 1);
    ReleaseSRWLockExclusive(&state_lock);
    record("local_identity_authorized", okay);
    return okay;
}

bool DFLocalRefresh(void) {
    char token[129]; INTERNET_PORT port;
    AcquireSRWLockShared(&state_lock);
    port = service_port; memcpy(token, session_token, sizeof token);
    ReleaseSRWLockShared(&state_lock);
    Identity fresh = {0};
    bool okay = fetch_identity(port, token, &fresh);
    SecureZeroMemory(token, sizeof token);
    AcquireSRWLockExclusive(&state_lock);
    if (!okay || fresh.id != identity.id) {
        okay = false;
        authorized = false;
        SecureZeroMemory(&identity, sizeof identity);
    } else identity = fresh;
    ReleaseSRWLockExclusive(&state_lock);
    record("local_identity_refreshed", okay);
    return okay;
}

static DWORD WINAPI identity_worker(LPVOID unused) {
    (void)unused;
    while (WaitForSingleObject(stop_event, 5000) == WAIT_TIMEOUT) {
        if (!DFLocalRefresh()) break;
    }
    return 0;
}

static bool logged_in(Object *self) {
    (void)self;
    AcquireSRWLockShared(&state_lock);
    bool result = initialized && authorized && identity.expires > unix_time();
    ReleaseSRWLockShared(&state_lock);
    record("player_logged_in", result);
    return result;
}

static NativeID *get_id(Object *self, NativeID *out) {
    (void)self;
    AcquireSRWLockShared(&state_lock);
    out->id = initialized && authorized && identity.expires > unix_time() ? identity.id : 0;
    ReleaseSRWLockShared(&state_lock);
    record("player_id_returned", out->id != 0);
    return out;
}

static uint32_t assign_string(NativeString *out, const char *source) {
    if (!out) return 2;
    size_t bytes = strlen(source) + 1;
    char *copy = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!copy) return 1;
    memcpy(copy, source, bytes);
    if (out->capacity && out->data) HeapFree(GetProcessHeap(), 0, out->data);
    out->data = copy; out->count = bytes; out->capacity = bytes;
    return 0;
}

static uint32_t get_name(Object *self, NativeString *out) {
    (void)self;
    char name[257];
    AcquireSRWLockShared(&state_lock);
    bool ready = initialized && authorized && identity.expires > unix_time();
    memcpy(name, identity.name, sizeof name);
    ReleaseSRWLockShared(&state_lock);
    record("player_name_requested", ready);
    return ready ? assign_string(out, name) : 1;
}

static uint32_t populate_local_account_info(NativeAccountInfo *out, uint64_t *used_id) {
    if (!out) return REQUEST_NOT_ACCEPTED;
    Identity current;
    char token[129], id_text[21], channel_text[11];
    AcquireSRWLockShared(&state_lock);
    bool ready = initialized && authorized && identity.expires > unix_time();
    current = identity;
    memcpy(token, session_token, sizeof token);
    ReleaseSRWLockShared(&state_lock);
    char *end = decimal(id_text, ready ? current.id : 0); *end = 0;
    end = decimal(channel_text, LOCAL_ACCOUNT_CHANNEL_ID); *end = 0;
    /* All values belong to our own local account service. Our deployment's
     * private channel ID and false real-name status assert no vendor account.
     */
    NativeAccountInfo fresh = {0};
    NativeString *targets[] = {&out->error_msg, &out->open_id, &out->token, &out->channel,
        &out->pf, &out->user_name, &out->pf_key, &out->picture_url, &out->ext_str,
        &out->register_channel_id};
    NativeString *copies[] = {&fresh.error_msg, &fresh.open_id, &fresh.token, &fresh.channel,
        &fresh.pf, &fresh.user_name, &fresh.pf_key, &fresh.picture_url, &fresh.ext_str,
        &fresh.register_channel_id};
    const char *values[] = {ready ? "" : "Local session unavailable", ready ? id_text : "",
        ready ? token : "", LOCAL_CLIENT_CHANNEL_NAME, "df-local", ready ? current.name : "", "", "",
        "", channel_text};
    uint32_t result = REQUEST_NOT_ACCEPTED;
    for (unsigned i = 0; i < 10; ++i) {
        if (!targets[i]->vtable || targets[i]->capacity > 8192 ||
            (targets[i]->capacity && (!targets[i]->data || targets[i]->count > targets[i]->capacity))) goto finish;
        copies[i]->vtable = targets[i]->vtable;
        if (assign_string(copies[i], values[i])) goto finish;
    }
    for (unsigned i = 0; i < 10; ++i) {
        if (targets[i]->capacity && targets[i]->data) {
            if (i == 2) SecureZeroMemory(targets[i]->data, (SIZE_T)targets[i]->capacity);
            HeapFree(GetProcessHeap(), 0, targets[i]->data);
        }
        *targets[i] = *copies[i];
        copies[i]->data = NULL;
    }
    out->error_code = ready ? 0 : REQUEST_NOT_ACCEPTED;
    out->token_expire_time = ready ? current.expires : 0;
    out->channel_id = LOCAL_ACCOUNT_CHANNEL_ID;
    out->real_name_auth = 0;
    result = ready ? 0 : REQUEST_NOT_ACCEPTED;
finish:
    if (used_id) *used_id = result == 0 ? current.id : 0;
    for (unsigned i = 0; i < 10; ++i) {
        if (copies[i]->data) {
            if (i == 2) SecureZeroMemory(copies[i]->data, (SIZE_T)copies[i]->capacity);
            HeapFree(GetProcessHeap(), 0, copies[i]->data);
        }
    }
    SecureZeroMemory(token, sizeof token);
    SecureZeroMemory(&current, sizeof current);
    return result;
}

static uint32_t get_local_account_info(Object *self, NativeAccountInfo *out) {
    (void)self;
    uint32_t result = populate_local_account_info(out, NULL);
    record("local_account_info_returned", result == 0);
    return result;
}

static uint32_t get_local_account_channel(Object *self, NativeString *out) {
    (void)self;
    uint32_t result = assign_string(out, LOCAL_CLIENT_CHANNEL_NAME);
    record("local_account_channel_returned", result == 0);
    return result;
}

static uint32_t get_account_type(Object *self) {
    (void)self;
    record_client_location("account_type_caller", __builtin_return_address(0));
    capture_known_client_code(__builtin_return_address(0), 0);
    AcquireSRWLockShared(&state_lock);
    bool ready = initialized && authorized && identity.expires > unix_time();
    ReleaseSRWLockShared(&state_lock);
    record("player_account_type_local_qq_compatibility", ready);
    /* Pinned client initialization labels type 1 as QQ. Its login-info
     * conversion separately maps the exact string QQ to channel 2.
     * These are compatibility selectors, not official credentials: identity,
     * token and expiry still come only from our authenticated local service.
     */
    return ready ? LOCAL_CLIENT_ACCOUNT_TYPE : 0;
}

static uint32_t report_player_game_action_unavailable(Object *self) {
    (void)self;
    /* The current local service has no game-action telemetry contract. Return
     * an explicit failure to the caller without terminating the game process.
     * No action arguments are read or exported from this diagnostic adapter. */
    record("local_player_game_action_report_unavailable", false);
    return REQUEST_NOT_ACCEPTED;
}

static NativeID *get_game_id(Object *self, NativeID *out) {
    (void)self; out->id = 2001918;
    record("game_id_returned", true);
    return out;
}

static uint32_t get_game_path(Object *self, NativeString *out) {
    (void)self;
    WCHAR path[2048];
    if (!adjacent_path(L"", path)) return 1;
    size_t n = wcslen(path);
    if (n && path[n - 1] == L'\\') path[--n] = 0;
    const WCHAR suffix[] = L"\\DeltaForce\\Binaries\\ThirdParty\\WeGame\\Win64";
    size_t suffix_n = wcslen(suffix);
    if (n <= suffix_n || wcscmp(path + n - suffix_n, suffix)) return 1;
    path[n - suffix_n] = 0;
    char encoded[6144];
    if (!WideCharToMultiByte(CP_UTF8, 0, path, -1, encoded, sizeof encoded, NULL, NULL)) return 1;
    record("game_path_returned", true);
    return assign_string(out, encoded);
}

static void *get_player(Object *self) { (void)self; record("factory_player_requested", true); return &player; }
static void *get_game(Object *self) { (void)self; record("factory_game_requested", true); return &game; }
static void *get_dlc(Object *self) { (void)self; record("factory_local_dlc_catalog_requested", true); return &dlc; }
static void *get_system(Object *self) { (void)self; record("factory_local_system_requested", true); return &local_system; }
static void *get_expansion(Object *self) { (void)self; record("factory_local_expansion_catalog_requested", true); return &expansion; }
static void *get_zone_helper(Object *self) { (void)self; record("factory_local_zone_helper_requested", true); return &zone_helper; }
static void *get_local_account(Object *self) { (void)self; record("factory_local_account_requested", true); return &local_account; }
static NativeID *get_local_root_zone(Object *self, NativeID *out) {
    (void)self;
    /* Identifier of this provider's own configured root, not a vendor zone. */
    out->id = 1;
    record("local_root_zone_id_returned", true);
    return out;
}
static NativeID *get_local_selected_zone(Object *self, NativeID *out) {
    (void)self;
    AcquireSRWLockShared(&state_lock);
    out->id = initialized && authorized && identity.expires > unix_time() ? 1 : 0;
    ReleaseSRWLockShared(&state_lock);
    record("local_selected_zone_id_returned", out->id != 0);
    return out;
}

static void *open_local_zone(Object *self, const NativeID *id, uint32_t *result) {
    (void)self;
    ZoneHandle *handle = NULL;
    AcquireSRWLockExclusive(&state_lock);
    bool ready = initialized && authorized && identity.expires > unix_time() &&
        id && id->id == 1 && zone_handle_count < 64;
    if (ready) {
        handle = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *handle);
        if (handle) {
            handle->vtable = zone_server_table; handle->zone_id = 1;
            handle->next = zone_handles; zone_handles = handle; ++zone_handle_count;
        }
    }
    ReleaseSRWLockExclusive(&state_lock);
    if (result) *result = handle ? 0 : REQUEST_NOT_ACCEPTED;
    record("local_zone_opened", handle != NULL);
    return handle;
}

static void release_local_zone(ZoneHandle *handle) {
    AcquireSRWLockExclusive(&state_lock);
    ZoneHandle **entry = &zone_handles;
    while (*entry && *entry != handle) entry = &(*entry)->next;
    bool found = *entry != NULL;
    if (found) { *entry = handle->next; --zone_handle_count; }
    ReleaseSRWLockExclusive(&state_lock);
    if (!found) DFLocalUnsupportedExport("local_zone_release_invalid_handle");
    HeapFree(GetProcessHeap(), 0, handle);
    record("local_zone_released", true);
}

static void *destroy_local_zone(ZoneHandle *handle, uint32_t flags) {
    if (flags != 1) DFLocalUnsupportedExport("unsupported_local_zone_destructor_flags");
    release_local_zone(handle);
    return handle;
}

static uint64_t local_zone_component_version(ZoneHandle *handle) {
    (void)handle;
    return 1; /* Version of our component, not a vendor SDK version claim. */
}

static NativeID *local_zone_id(ZoneHandle *handle, NativeID *out) {
    out->id = handle->zone_id;
    record("local_zone_id_returned", true);
    return out;
}

static uint32_t local_zone_name(ZoneHandle *handle, const NativeString *language, NativeString *out) {
    (void)language;
    return handle->zone_id == 1 ? assign_string(out, "Local") : REQUEST_NOT_ACCEPTED;
}

static uint32_t fill_local_zone_strings(ZoneHandle *handle, NativeStringArray *out,
                                       const char *const *values, uint64_t count) {
    AcquireSRWLockShared(&state_lock);
    bool ready = initialized && authorized && identity.expires > unix_time() && handle->zone_id == 1;
    VFn *string_table = client_string_table;
    ReleaseSRWLockShared(&state_lock);
    if (!ready || !string_table || !out || !values || !count || count > 64 || out->capacity > 64 ||
        (out->capacity && (out->count > out->capacity || !out->data))) return REQUEST_NOT_ACCEPTED;
    NativeString *items = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count * sizeof *items);
    if (!items) return REQUEST_NOT_ACCEPTED;
    for (uint64_t i = 0; i < count; ++i) {
        items[i].vtable = string_table;
        if (assign_string(&items[i], values[i])) {
            for (uint64_t j = 0; j <= i; ++j) {
                if (items[j].capacity && items[j].data)
                    HeapFree(GetProcessHeap(), 0, items[j].data);
            }
            HeapFree(GetProcessHeap(), 0, items); return REQUEST_NOT_ACCEPTED;
        }
    }
    /* The caller's array vptr is preserved. Elements use the caller's string
     * code vptr observed in its prior catalog request, with independently
     * owned process-heap storage. Borrowed old arrays have capacity zero.
     */
    if (out->capacity && out->data) {
        for (uint64_t i = 0; i < out->count; ++i) {
            if (out->data[i].capacity && out->data[i].data)
                HeapFree(GetProcessHeap(), 0, out->data[i].data);
        }
        HeapFree(GetProcessHeap(), 0, out->data);
    }
    out->data = items; out->count = out->capacity = count;
    return 0;
}

static uint32_t local_zone_languages(ZoneHandle *handle, NativeStringArray *out) {
    /* Languages describe our own zone catalog, independently of vendor zones. */
    const char *const languages[] = {"zh-CN"};
    uint32_t result = fill_local_zone_strings(handle, out, languages, 1);
    record("local_zone_languages_returned", result == 0);
    return result;
}

static uint32_t local_zone_addresses(ZoneHandle *handle, NativeStringArray *out) {
    const char *const addresses[] = {"127.0.0.1:65010"};
    uint32_t result = fill_local_zone_strings(handle, out, addresses, 1);
    record("local_zone_addresses_returned", result == 0);
    return result;
}
static uint32_t get_empty_expansion_count(Object *self) {
    (void)self;
    record("local_expansion_catalog_count_zero", true);
    return 0;
}
static uint32_t get_local_distribute_id(Object *self, NativeString *out) {
    (void)self;
    AcquireSRWLockShared(&state_lock);
    bool ready = initialized && authorized && identity.expires > unix_time();
    ReleaseSRWLockShared(&state_lock);
    uint32_t result = ready ? assign_string(out, "df-local") : REQUEST_NOT_ACCEPTED;
    record("system_local_distribute_id_returned", result == 0);
    return result;
}
static uint32_t get_empty_dlc_count(Object *self) {
    (void)self;
    record("local_dlc_catalog_count_zero", true);
    /* Our local optional-content catalog has no entries. This count does
     * not assert ownership, installation, or availability of vendor DLC.
     */
    return 0;
}
static bool local_is_dlc_installed(Object *self, const void *dlc_id, const void *optional_result) {
    (void)self; (void)dlc_id; (void)optional_result;
    /* The local optional-content catalog is empty. No vendor DLC installation
     * or ownership state is available through this independent provider.
     */
    record("local_dlc_installation_absent", false);
    return false;
}

static void destroy_pending(PendingEvent *event) {
    if (event->event_id == LOCAL_ACCOUNT_LOGIN_EVENT) {
        NativeString *fields[] = {&event->account_info.error_msg, &event->account_info.open_id,
            &event->account_info.token, &event->account_info.channel, &event->account_info.pf,
            &event->account_info.user_name, &event->account_info.pf_key, &event->account_info.picture_url,
            &event->account_info.ext_str, &event->account_info.register_channel_id};
        for (unsigned i = 0; i < 10; ++i) {
            if (fields[i]->capacity && fields[i]->data) {
                if (i == 2) SecureZeroMemory(fields[i]->data, (SIZE_T)fields[i]->capacity);
                HeapFree(GetProcessHeap(), 0, fields[i]->data);
            }
        }
    }
    if (event->data.user_data.data) HeapFree(GetProcessHeap(), 0, event->data.user_data.data);
    HeapFree(GetProcessHeap(), 0, event);
}

static void borrowed_event_delete(void) {
    /* Event pointers are borrowed during OnRailEvent; the provider owns them. */
    DFLocalUnsupportedExport("unsupported_delete_borrowed_local_event");
}

static uint32_t ready_event_id(EventBase *self) { (void)self; return LOCAL_CATALOG_READY_EVENT; }
static uint32_t expansion_event_id(EventBase *self) { (void)self; return LOCAL_EXPANSION_LIST_EVENT; }
static uint32_t account_event_id(EventBase *self) { (void)self; return LOCAL_ACCOUNT_LOGIN_EVENT; }

static const char *queued_event_name(uint32_t id) {
    return id == LOCAL_CATALOG_READY_EVENT ? "local_dlc_catalog_ready_queued" :
        id == LOCAL_EXPANSION_LIST_EVENT ? "local_expansion_catalog_list_queued" : "local_account_login_queued";
}
static const char *dispatch_event_name(uint32_t id) {
    return id == LOCAL_CATALOG_READY_EVENT ? "local_dlc_catalog_ready_dispatch" :
        id == LOCAL_EXPANSION_LIST_EVENT ? "local_expansion_catalog_list_dispatch" : "local_account_login_dispatch";
}
static const char *returned_event_name(uint32_t id) {
    return id == LOCAL_CATALOG_READY_EVENT ? "local_dlc_catalog_ready_callback_returned" :
        id == LOCAL_EXPANSION_LIST_EVENT ? "local_expansion_catalog_list_callback_returned" : "local_account_login_callback_returned";
}

static uint32_t queue_local_catalog_event(const NativeString *context, uint32_t event_id) {
    /* Bound a caller-owned C++ string before making an independent copy.
     * Its vptr is a code address, retained for the duration of the callback;
     * the borrowed source data is never retained.
     */
    if (!context || !context->data || !context->count || context->count > 4097 ||
        (context->capacity && context->capacity < context->count) ||
        context->data[context->count - 1] != 0 ||
        memchr(context->data, 0, (size_t)context->count - 1)) return REQUEST_NOT_ACCEPTED;
    PendingEvent *event = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *event);
    if (!event) return REQUEST_NOT_ACCEPTED;
    event->event_id = event_id;
    event->data.vtable = event_id == LOCAL_CATALOG_READY_EVENT ? ready_event_table :
        event_id == LOCAL_EXPANSION_LIST_EVENT ? expansion_event_table : account_event_table;
    event->data.user_data.vtable = context->vtable;
    if (assign_string(&event->data.user_data, context->data)) {
        destroy_pending(event); return REQUEST_NOT_ACCEPTED;
    }
    uint64_t account_id = 0;
    if (event_id == LOCAL_ACCOUNT_LOGIN_EVENT) {
        if (!context->vtable) { destroy_pending(event); return REQUEST_NOT_ACCEPTED; }
        NativeString *fields[] = {&event->account_info.error_msg, &event->account_info.open_id,
            &event->account_info.token, &event->account_info.channel, &event->account_info.pf,
            &event->account_info.user_name, &event->account_info.pf_key, &event->account_info.picture_url,
            &event->account_info.ext_str, &event->account_info.register_channel_id};
        for (unsigned i = 0; i < 10; ++i) fields[i]->vtable = context->vtable;
        if (populate_local_account_info(&event->account_info, &account_id)) {
            destroy_pending(event); return REQUEST_NOT_ACCEPTED;
        }
    }
    AcquireSRWLockExclusive(&state_lock);
    bool ready = initialized && authorized && identity.expires > unix_time() &&
        (event_id != LOCAL_ACCOUNT_LOGIN_EVENT || (identity.id == account_id &&
            !strcmp(event->account_info.token.data, session_token)));
    event->data.rail_id = ready ? identity.id : 0;
    if (ready && context->vtable) client_string_table = context->vtable;
    event->data.game_id = 2001918;
    /* Success reports the actual readiness of our empty local catalog.
     * No vendor ownership or installation result is asserted.
     */
    event->data.result = 0;
    AcquireSRWLockExclusive(&event_lock);
    bool queued = ready && pending_count < 32;
    if (queued) {
        if (pending_tail) pending_tail->next = event; else pending_head = event;
        pending_tail = event; ++pending_count;
    }
    ReleaseSRWLockExclusive(&event_lock);
    ReleaseSRWLockExclusive(&state_lock);
    if (!queued) destroy_pending(event);
    record(queued_event_name(event_id), queued);
    return queued ? 0 : REQUEST_NOT_ACCEPTED;
}

static uint32_t async_local_catalog_ready(Object *self, const NativeString *context) {
    (void)self;
    return queue_local_catalog_event(context, LOCAL_CATALOG_READY_EVENT);
}

static uint32_t async_local_expansion_list(Object *self, const NativeString *context) {
    (void)self;
    return queue_local_catalog_event(context, LOCAL_EXPANSION_LIST_EVENT);
}

static uint32_t async_local_account_login(Object *self, const NativeString *context) {
    (void)self;
    /* Auto-login reuses only the authenticated bootstrap of our local service. */
    return queue_local_catalog_event(context, LOCAL_ACCOUNT_LOGIN_EVENT);
}

/* Generated fixed-version slot failures and export definitions. */
#include "provider_slots.inc"

static BOOL CALLBACK initialize_tables(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    (void)once; (void)parameter; (void)context;
    set_unknown_slots();
    SET_SLOT(factory_table, 0, get_player); SET_SLOT(factory_table, 16, get_game);
    SET_SLOT(factory_table, 19, get_dlc);
    SET_SLOT(factory_table, 22, get_system);
    SET_SLOT(factory_table, 34, get_expansion);
    SET_SLOT(factory_table, 27, get_zone_helper);
    SET_SLOT(factory_table, 32, get_local_account);
    SET_SLOT(local_account_table, 0, async_local_account_login);
    SET_SLOT(local_account_table, 2, get_local_account_info);
    SET_SLOT(local_account_table, 5, get_local_account_channel);
    SET_SLOT(player_table, 0, logged_in); SET_SLOT(player_table, 1, get_id); SET_SLOT(player_table, 7, get_name);
    SET_SLOT(player_table, 16, get_account_type);
    SET_SLOT(player_table, 18, report_player_game_action_unavailable);
    SET_SLOT(game_table, 0, get_game_id); SET_SLOT(game_table, 2, get_game_path);
    SET_SLOT(dlc_table, 4, get_empty_dlc_count);
    SET_SLOT(dlc_table, 1, async_local_catalog_ready);
    SET_SLOT(dlc_table, 2, local_is_dlc_installed);
    SET_SLOT(system_table, 2, get_local_distribute_id);
    SET_SLOT(expansion_table, 1, get_empty_expansion_count);
    SET_SLOT(expansion_table, 0, async_local_expansion_list);
    SET_SLOT(zone_helper_table, 0, get_local_selected_zone);
    SET_SLOT(zone_helper_table, 1, get_local_root_zone);
    SET_SLOT(zone_helper_table, 2, open_local_zone);
    SET_SLOT(zone_server_table, 0, local_zone_component_version);
    SET_SLOT(zone_server_table, 1, release_local_zone);
    SET_SLOT(zone_server_table, 2, destroy_local_zone);
    SET_SLOT(zone_server_table, 3, local_zone_id);
    SET_SLOT(zone_server_table, 4, local_zone_languages);
    SET_SLOT(zone_server_table, 5, local_zone_name);
    SET_SLOT(zone_server_table, 6, local_zone_languages);
    SET_SLOT(zone_server_table, 7, local_zone_name);
    SET_SLOT(zone_server_table, 8, local_zone_addresses);
    SET_SLOT(ready_event_table, 0, borrowed_event_delete);
    SET_SLOT(ready_event_table, 1, ready_event_id);
    SET_SLOT(expansion_event_table, 0, borrowed_event_delete);
    SET_SLOT(expansion_event_table, 1, expansion_event_id);
    SET_SLOT(account_event_table, 0, borrowed_event_delete);
    SET_SLOT(account_event_table, 1, account_event_id);
    return TRUE;
}

bool RailNeedRestartAppForCheckingEnvironment(uint64_t game_id, int argc, const char **argv) {
    (void)argc; (void)argv;
    record("startup_check_enter", -1);
    char config[141];
    DWORD length = read_adjacent(L"df_local_identity_bootstrap.bin", config, sizeof config);
    uint16_t version = 0, port = 0, token_n = 0, reserved = 0;
    if (length >= 12) {
        memcpy(&version, config + 4, 2); memcpy(&port, config + 6, 2);
        memcpy(&token_n, config + 8, 2); memcpy(&reserved, config + 10, 2);
    }
    bool valid = game_id == 2001918 && length >= 13 && !memcmp(config, "DFLC", 4) && version == 1 &&
        !reserved && token_n && token_n < 128 && length == 12u + token_n;
    char token[129] = {0};
    if (valid) memcpy(token, config + 12, token_n);
    bool ready = valid && DFLocalAuthorize(port, token);
    SecureZeroMemory(token, sizeof token); SecureZeroMemory(config, sizeof config);
    record("startup_check_exit", !ready);
    return !ready;
}

bool RailInitialize(void) {
    record("initialize_enter", -1);
    AcquireSRWLockExclusive(&state_lock);
    bool ready = authorized && identity.expires > unix_time();
    if (initialized) { ReleaseSRWLockExclusive(&state_lock); return ready; }
    ReleaseSRWLockExclusive(&state_lock);
    if (!ready || !InitOnceExecuteOnce(&tables_once, initialize_tables, NULL, NULL)) {
        record("initialize_exit", false); return false;
    }
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event) { record("initialize_exit", false); return false; }
    worker_thread = CreateThread(NULL, 0, identity_worker, NULL, 0, NULL);
    if (!worker_thread) { CloseHandle(stop_event); stop_event = NULL; record("initialize_exit", false); return false; }
    AcquireSRWLockExclusive(&state_lock); initialized = true; ReleaseSRWLockExclusive(&state_lock);
    record("initialize_exit", true);
    return true;
}

void RailFinalize(void) {
    record("finalize_enter", -1);
    if (stop_event) SetEvent(stop_event);
    if (worker_thread) {
        if (WaitForSingleObject(worker_thread, 10000) != WAIT_OBJECT_0) DFLocalUnsupportedExport("identity_worker_shutdown_failed");
        CloseHandle(worker_thread); worker_thread = NULL;
    }
    if (stop_event) { CloseHandle(stop_event); stop_event = NULL; }
    AcquireSRWLockExclusive(&state_lock);
    initialized = authorized = false;
    SecureZeroMemory(&identity, sizeof identity); SecureZeroMemory(session_token, sizeof session_token);
    service_port = 0;
    ZoneHandle *discard_zones = zone_handles;
    zone_handles = NULL; zone_handle_count = 0; client_string_table = NULL;
    AcquireSRWLockExclusive(&event_lock);
    PendingEvent *discard = pending_head;
    pending_head = pending_tail = NULL; pending_count = 0;
    memset(registrations, 0, sizeof registrations);
    ReleaseSRWLockExclusive(&event_lock);
    ReleaseSRWLockExclusive(&state_lock);
    while (discard) { PendingEvent *next = discard->next; destroy_pending(discard); discard = next; }
    while (discard_zones) { ZoneHandle *next = discard_zones->next; HeapFree(GetProcessHeap(), 0, discard_zones); discard_zones = next; }
    record("finalize_exit", -1);
}

void *RailFactory(void) {
    AcquireSRWLockShared(&state_lock); bool ready = initialized; ReleaseSRWLockShared(&state_lock);
    record("factory_returned", ready);
    return ready ? &factory : NULL;
}

void RailFireEvents(void) {
    if (InterlockedIncrement(&pump_count) <= 8) record("event_pump_returned", -1);
    if (InterlockedCompareExchange(&pumping, 1, 0)) return;
    /* A bounded snapshot leaves requests made by a callback for the next pump. */
    AcquireSRWLockShared(&event_lock);
    unsigned budget = pending_count;
    ReleaseSRWLockShared(&event_lock);
    while (budget--) {
        Registration listeners[128]; unsigned listener_count = 0;
        AcquireSRWLockExclusive(&event_lock);
        PendingEvent *event = pending_head;
        if (event) {
            pending_head = event->next;
            if (!pending_head) pending_tail = NULL;
            --pending_count;
            for (unsigned i = 0; i < 128; ++i) {
                if (registrations[i].listener && registrations[i].id == event->event_id)
                    listeners[listener_count++] = registrations[i];
            }
        }
        ReleaseSRWLockExclusive(&event_lock);
        if (!event) break;
        for (unsigned i = 0; i < listener_count; ++i) {
            AcquireSRWLockShared(&state_lock);
            bool current = initialized && authorized && identity.expires > unix_time() &&
                identity.id == event->data.rail_id &&
                (event->event_id != LOCAL_ACCOUNT_LOGIN_EVENT ||
                    !strcmp(event->account_info.token.data, session_token));
            ReleaseSRWLockShared(&state_lock);
            AcquireSRWLockShared(&event_lock);
            bool registered = false;
            for (unsigned j = 0; j < 128; ++j) {
                Registration *entry = &registrations[j];
                if (entry->listener == listeners[i].listener && entry->id == listeners[i].id &&
                    entry->generation == listeners[i].generation) { registered = true; break; }
            }
            ReleaseSRWLockShared(&event_lock);
            if (current && registered) {
                Object *listener = listeners[i].listener;
                typedef void (*OnRailEvent)(void *, uint32_t, const EventBase *);
                OnRailEvent callback;
                memcpy(&callback, &listener->vtable[0], sizeof callback);
                if (event->event_id == LOCAL_ACCOUNT_LOGIN_EVENT) {
                    record_client_location("login_callback", (const void *)callback);
                    record_client_location("login_listener_vtable", listener->vtable);
                    capture_known_client_code((const void *)callback, 1);
                    capture_known_client_code((const void *)callback, 3);
                    capture_known_client_code((const void *)callback, 4);
                }
                record(dispatch_event_name(event->event_id), true);
                /* No locks are held across a reentrant application callback. */
                callback(listener, event->event_id, &event->data);
                if (event->event_id == LOCAL_ACCOUNT_LOGIN_EVENT)
                    capture_known_client_code((const void *)callback, 2);
                record(returned_event_name(event->event_id), true);
            }
        }
        destroy_pending(event);
    }
    InterlockedExchange(&pumping, 0);
}

void RailRegisterEvent(uint32_t event_id, void *listener) {
    if (!listener) return;
    AcquireSRWLockExclusive(&event_lock);
    int free_index = -1;
    for (unsigned i = 0; i < 128; ++i) {
        if (registrations[i].listener == listener && registrations[i].id == event_id) {
            ReleaseSRWLockExclusive(&event_lock); return;
        }
        if (!registrations[i].listener && free_index < 0) free_index = (int)i;
    }
    if (free_index >= 0) registrations[free_index] = (Registration){event_id, listener, ++registration_generation};
    ReleaseSRWLockExclusive(&event_lock);
    if (free_index < 0) DFLocalUnsupportedExport("local_event_listener_capacity_exceeded");
    char event[96], *out = append(event, "event_listener_registered_");
    out = decimal(out, event_id); *out = 0;
    record(event, -1);
}

void RailUnregisterEvent(uint32_t event_id, void *listener) {
    AcquireSRWLockExclusive(&event_lock);
    for (unsigned i = 0; i < 128; ++i) {
        if (registrations[i].id == event_id && registrations[i].listener == listener)
            memset(&registrations[i], 0, sizeof registrations[i]);
    }
    ReleaseSRWLockExclusive(&event_lock);
    record("event_listener_unregistered", -1);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) self_module = instance;
    return TRUE;
}
