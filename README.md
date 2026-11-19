# cheat-paladins
// Paladins external — ESP + aimbot. x64, admin, janela sem bordas.
#include <windows.h>
#include <TlHelp32.h>
#include <d2d1.h>
#include <dwrite.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// ==================== OFFSETS ====================
namespace off {
    constexpr uint64_t ENGINE_FALLBACK[] = { 0x399E808, 0x39987E8, 0x3991708, 0x399C7E8 };
    constexpr const char* SIG_ENGINE_A = "48 8B 0D ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 39 B9 ? ? ? ?";
    constexpr const char* SIG_ENGINE_B = "48 8B 05 ? ? ? ? 4C 8B 04 0A 4C 33 04 F0 44";

    constexpr uint64_t LOCALPLAYER = 0x6D8, CONTROLLER = 0x68, ROTATION = 0x8C;
    constexpr uint64_t WORLD_INFO = 0x120, ACK_PAWN = 0x498, CAMERA = 0x478;
    constexpr uint64_t FOV_MULT = 0x4CC, REAL_LOCATION = 0x494, DEFAULT_FOV = 0x290;
    constexpr uint64_t PAWN_LIST = 0x5B4, TIME_SECONDS = 0x4EC;
    constexpr uint64_t LOCATION = 0x80, VELOCITY = 0x190, HEALTH_READ = 0x3C4;
    constexpr uint64_t MAX_HEALTH = 0x117C, REPL_INFO = 0x440, NEXT_PAWN = 0x2AC;
    constexpr uint64_t MESH = 0x48C, EYE_HEIGHT = 0x3A4, WEAPON = 0x4E4;
    constexpr uint64_t TEAM = 0x4DC, TEAM_INDEX = 0x298, PLAYER_NAME = 0x290;
    constexpr uint64_t BOUNDS = 0xA0, LAST_RENDER = 0x244;
    constexpr uint64_t RECOIL = 0x96C, ACCURACY = 0x8CC, PROJECTILES = 0x614, PROJ_SPEED = 0x280;
}

// ==================== MEM ====================
static HANDLE   g_hProc = nullptr;
static uint64_t g_Base = 0;
static size_t   g_ImageSize = 0;
static uint64_t g_EnginePtrAddr = 0;

static inline bool AddrOk(uint64_t a) {
    return a > 0x10000 && a < 0x7FFFFFFFFFFFULL && a != 0xCCCCCCCCCCCCCCCCULL;
}

template<typename T> static inline T RPM(uint64_t a) {
    T o{};
    if (!AddrOk(a)) return o;
    SIZE_T n = 0;
    ReadProcessMemory(g_hProc, (LPCVOID)a, &o, sizeof(T), &n);
    return (n == sizeof(T)) ? o : T{};
}
template<typename T> static inline bool WPM(uint64_t a, T v) {
    if (!AddrOk(a)) return false;
    SIZE_T n = 0;
    return WriteProcessMemory(g_hProc, (LPVOID)a, &v, sizeof(T), &n) && n == sizeof(T);
}
static inline bool ReadBuf(uint64_t a, void* b, size_t s) {
    if (!AddrOk(a)) return false;
    SIZE_T n = 0;
    return ReadProcessMemory(g_hProc, (LPCVOID)a, b, s, &n) && n == s;
}

static DWORD GetPid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) do {
        if (!_wcsicmp(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static uint64_t GetModuleBase(DWORD pid, const wchar_t* mod) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{ sizeof(me) };
    uint64_t b = 0;
    if (Module32FirstW(snap, &me)) do {
        if (!_wcsicmp(me.szModule, mod)) { b = (uint64_t)me.modBaseAddr; break; }
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return b;
}

static bool GetTextRange(uint64_t base, uint64_t& s, uint64_t& e) {
    IMAGE_DOS_HEADER dos = RPM<IMAGE_DOS_HEADER>(base);
    if (dos.e_magic != IMAGE_DOS_HEADER_SIGNATURE) return false;
    IMAGE_NT_HEADERS64 nt = RPM<IMAGE_NT_HEADERS64>(base + dos.e_lfanew);
    if (nt.Signature != IMAGE_NT_SIGNATURE) return false;
    g_ImageSize = nt.OptionalHeader.SizeOfImage;
    uint64_t sec = base + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    for (int i = 0; i < nt.FileHeader.NumberOfSections; i++, sec += sizeof(IMAGE_SECTION_HEADER)) {
        IMAGE_SECTION_HEADER sh = RPM<IMAGE_SECTION_HEADER>(sec);
        if (!memcmp(sh.Name, ".text", 5)) {
            s = base + sh.VirtualAddress;
            e = s + sh.Misc.VirtualSize;
            return e > s;
        }
    }
    return false;
}

static uint64_t ScanEngine() {
    uint64_t s = 0, e = 0;
    if (!GetTextRange(g_Base, s, e)) return 0;
    size_t size = (size_t)(e - s);
    if (size > (64u << 20)) size = 64u << 20;
    std::vector<uint8_t> buf(size);
    if (!ReadBuf(s, buf.data(), size)) return 0;

    const char* sigs[] = { off::SIG_ENGINE_A, off::SIG_ENGINE_B };
    for (const char* sig : sigs) {
        std::vector<uint8_t> pat; std::vector<bool> wild;
        for (const char* p = sig; *p;) {
            if (*p == ' ') { p++; continue; }
            if (*p == '?') { pat.push_back(0); wild.push_back(true); p++; continue; }
            pat.push_back((uint8_t)strtoul(p, (char**)&p, 16)); wild.push_back(false);
        }
        if (pat.size() < 8 || size < pat.size()) continue;
        for (size_t i = 0; i + pat.size() <= size; i++) {
            bool ok = true;
            for (size_t j = 0; j < pat.size(); j++)
                if (!wild[j] && buf[i + j] != pat[j]) { ok = false; break; }
            if (!ok) continue;
            int32_t disp = RPM<int32_t>(s + i + 3);
            uint64_t target = s + i + 7 + disp;
            uint64_t eng = RPM<uint64_t>(target);
            if (eng >= g_Base && eng < g_Base + g_ImageSize) return target;
        }
    }
    return 0;
}

static bool ResolveEngine() {
    uint64_t a = ScanEngine();
    if (a) { g_EnginePtrAddr = a; return true; }
    for (uint64_t fb : off::ENGINE_FALLBACK) {
        uint64_t cand = g_Base + fb;
        uint64_t eng = RPM<uint64_t>(cand);
        if (eng >= g_Base && eng < g_Base + g_ImageSize) { g_EnginePtrAddr = cand; return true; }
    }
    return false;
}

// ==================== SDK ====================
struct FVector {
    float X, Y, Z;
    FVector() : X(0), Y(0), Z(0) {}
    FVector(float x, float y, float z) : X(x), Y(y), Z(z) {}
    FVector operator-(const FVector& o) const { return { X - o.X, Y - o.Y, Z - o.Z }; }
    float Size() const { return sqrtf(X * X + Y * Y + Z * Z); }
};
struct FRotator { int32_t Pitch, Yaw, Roll; };
struct FBoxSphereBounds { FVector Origin, BoxExtent; float SphereRadius; };

template<typename T> struct TArray {
    uint64_t Data; int32_t Count, Max;
    bool Valid() const { return Data && Count > 0 && Count <= Max; }
    T At(int i) const { return RPM<T>(Data + (uint64_t)i * 8); }
};
struct FString : TArray<wchar_t> {
    std::wstring W() const {
        if (!Valid() || Count > 256) return L"";
        std::wstring s((size_t)Count, L'\0');
        ReadBuf(Data, s.data(), (size_t)Count * sizeof(wchar_t));
        while (!s.empty() && (s.back() == 0 || s.back() == L'\n')) s.pop_back();
        return s;
    }
};
struct UEngine { uint64_t p; };
struct ULocalPlayer { uint64_t p; };
struct APlayerController { uint64_t p; };
struct AWorldInfo { uint64_t p; };
struct ACamera { uint64_t p; };
struct APawn { uint64_t p; };
struct ATgDevice { uint64_t p; };
struct USkeletalMesh { uint64_t p; };
struct ARepInfo { uint64_t p; };
struct ATeamInfo { uint64_t p; };

static inline UEngine GetEngine() { return { RPM<uint64_t>(g_EnginePtrAddr) }; }
static inline ULocalPlayer GetLP(UEngine e) { return { RPM<uint64_t>(e.p + off::LOCALPLAYER) }; }
static inline APlayerController GetCtrl(ULocalPlayer l) { return { RPM<uint64_t>(l.p + off::CONTROLLER) }; }
static inline AWorldInfo GetWI(APlayerController c) { return { RPM<uint64_t>(c.p + off::WORLD_INFO) }; }
static inline ACamera GetCam(APlayerController c) { return { RPM<uint64_t>(c.p + off::CAMERA) }; }
static inline APawn GetPawn(APlayerController c) { return { RPM<uint64_t>(c.p + off::ACK_PAWN) }; }
static inline FRotator GetRot(APlayerController c) { return RPM<FRotator>(c.p + off::ROTATION); }
static inline void SetRot(APlayerController c, FRotator r) { WPM<FRotator>(c.p + off::ROTATION, r); }
static inline float GetFovMul(APlayerController c) { return RPM<float>(c.p + off::FOV_MULT); }
static inline FVector GetCamLoc(ACamera c) { return RPM<FVector>(c.p + off::REAL_LOCATION); }
static inline float GetDefFov(ACamera c) { return RPM<float>(c.p + off::DEFAULT_FOV); }
static inline float GetTimeSeconds(AWorldInfo w) { return RPM<float>(w.p + off::TIME_SECONDS); }
static inline APawn GetPawnList(AWorldInfo w) { return { RPM<uint64_t>(w.p + off::PAWN_LIST) }; }
static inline APawn NextPawn(APawn p) { return { RPM<uint64_t>(p.p + off::NEXT_PAWN) }; }
static inline int GetHealth(APawn p) { return RPM<int32_t>(p.p + off::HEALTH_READ); }
static inline int GetMaxHealth(APawn p) { return (int)RPM<float>(p.p + off::MAX_HEALTH); }
static inline FVector GetLoc(APawn p) { return RPM<FVector>(p.p + off::LOCATION); }
static inline FVector GetVel(APawn p) { return RPM<FVector>(p.p + off::VELOCITY); }
static inline float GetEye(APawn p) { return RPM<float>(p.p + off::EYE_HEIGHT); }
static inline USkeletalMesh GetMesh(APawn p) { return { RPM<uint64_t>(p.p + off::MESH) }; }
static inline ATgDevice GetWeapon(APawn p) { return { RPM<uint64_t>(p.p + off::WEAPON) }; }
static inline ARepInfo GetRep(APawn p) { return { RPM<uint64_t>(p.p + off::REPL_INFO) }; }
static inline ATeamInfo GetTeam(ARepInfo r) { return { RPM<uint64_t>(r.p + off::TEAM) }; }
static inline int GetTeamIdx(ATeamInfo t) { return RPM<int32_t>(t.p + off::TEAM_INDEX); }
static inline std::wstring GetName(ARepInfo r) { return RPM<FString>(r.p + off::PLAYER_NAME).W(); }
static inline FBoxSphereBounds GetBounds(USkeletalMesh m) { return RPM<FBoxSphereBounds>(m.p + off::BOUNDS); }
static inline float GetLastRender(USkeletalMesh m) { return RPM<float>(m.p + off::LAST_RENDER); }
static inline bool IsVisible(USkeletalMesh m, float now) { return GetLastRender(m) > now - 0.05f; }

struct FRecoilSettings { int32_t Uses; float Reduction, Delay, Smooth; };
struct FAccuracySettings { int32_t Adv; float Max, Min, Loss, Gain, GainDelay; int32_t FreeShots; };

static inline void NoRecoil(ATgDevice d) {
    FRecoilSettings s = RPM<FRecoilSettings>(d.p + off::RECOIL);
    s.Uses = 0; s.Reduction = 0.f; s.Delay = 0.f; s.Smooth = 0.f;
    WPM<FRecoilSettings>(d.p + off::RECOIL, s);
}
static inline void NoSpread(ATgDevice d) {
    FAccuracySettings s = RPM<FAccuracySettings>(d.p + off::ACCURACY);
    s.Max = 1.f; s.Min = 1.f; s.Gain = 0.f;
    WPM<FAccuracySettings>(d.p + off::ACCURACY, s);
}
static inline float GetProjSpeed(ATgDevice d) {
    TArray<uint64_t> a = RPM<TArray<uint64_t>>(d.p + off::PROJECTILES);
    if (!a.Valid()) return 0.f;
    uint64_t pr = a.At(0);
    return AddrOk(pr) ? RPM<float>(pr + off::PROJ_SPEED) : 0.f;
}

// ==================== OVERLAY ====================
struct Vec2 { float x, y; };

class Overlay {
public:
    HWND hwnd = nullptr;
    bool Init() {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"pdovl";
        RegisterClassExW(&wc);
        hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW,
                               L"pdovl", L"", WS_POPUP, 0, 0, 8, 8, nullptr, nullptr, wc.hInstance, nullptr);
        if (!hwnd) return false;
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &fac))) return false;
        if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), (IUnknown**)&dw))) return false;
        if (FAILED(dw->CreateTextFormat(L"Consolas", nullptr, DWRITE_FONT_WEIGHT_BOLD,
            DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, 12.f, L"", &fmt))) return false;
        D2D1_RENDER_TARGET_PROPERTIES rtp = D2D1::RenderTargetProperties(
            D2D1_RENDER_TARGET_TYPE_DEFAULT,
            D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));
        return SUCCEEDED(fac->CreateDCRenderTarget(&rtp, &rt));
    }
    void SetBounds(int x, int y, int w, int h) {
        if (w == W && h == H && x == px && y == py) return;
        px = x; py = y; W = w; H = h;
        if (br) { br->Release(); br = nullptr; }
        if (dib) { DeleteObject(dib); dib = nullptr; }
        if (hdc) { DeleteDC(hdc); hdc = nullptr; }
        if (w <= 0 || h <= 0) return;
        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        HDC scr = GetDC(nullptr);
        hdc = CreateCompatibleDC(scr);
        dib = CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, nullptr, nullptr, 0);
        SelectObject(hdc, dib);
        ReleaseDC(nullptr, scr);
        SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
    void Begin() {
        if (!dib || !rt) return;
        RECT rc{ 0, 0, (LONG)W, (LONG)H };
        rt->BindDC(hdc, &rc);
        rt->BeginDraw();
        rt->Clear(D2D1::ColorF(0.f, 0.f, 0.f, 0.f));
    }
    void End() {
        if (!dib || !rt) return;
        rt->EndDraw();
        HDC scr = GetDC(nullptr);
        POINT src{ 0, 0 }, dst{ px, py };
        SIZE sz{ (LONG)W, (LONG)H };
        BLENDFUNCTION bf{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
        UpdateLayeredWindow(hwnd, scr, &dst, &sz, hdc, &src, 0, &bf, ULW_ALPHA);
        ReleaseDC(nullptr, scr);
    }
    void Line(float x1, float y1, float x2, float y2, D2D1_COLOR_F c, float t = 1.f) {
        rt->DrawLine(D2D1::Point2F(x1, y1), D2D1::Point2F(x2, y2), B(c), t);
    }
    void FillRect(float x1, float y1, float x2, float y2, D2D1_COLOR_F c) {
        rt->FillRectangle(D2D1::RectF(x1, y1, x2, y2), B(c));
    }
    void Text(float x, float y, D2D1_COLOR_F c, const wchar_t* s) {
        rt->DrawTextW(s, (UINT32)wcslen(s), fmt, D2D1::RectF(x, y, (float)W, y + 20.f), B(c));
    }
private:
    ID2D1SolidColorBrush* B(D2D1_COLOR_F c) {
        if (br) { br->Release(); br = nullptr; }
        rt->CreateSolidColorBrush(c, &br);
        return br;
    }
    ID2D1Factory* fac = nullptr; IDWriteFactory* dw = nullptr; IDWriteTextFormat* fmt = nullptr;
    ID2D1DCRenderTarget* rt = nullptr; ID2D1SolidColorBrush* br = nullptr;
    HDC hdc = nullptr; HBITMAP dib = nullptr;
    int px = 0, py = 0, W = 0, H = 0;
};

// ==================== GAME ====================
static constexpr int   UR180 = 32768;
static constexpr float RAD2UR = 10430.3783504704527f;
static constexpr float UR2RAD = 0.00009587379924285f;
static constexpr float PIF = 3.14159265358979323f;

static bool  cEsp = true, cAim = true, cTracer = true, cPred = true, cNoRecoil = true;
static float cSmooth = 0.25f, cAimFov = 40.f, cMaxDist = 25000.f;
static Overlay ovl;
static int scrW = 0, scrH = 0;
static float cx = 0.f, cy = 0.f;
static HWND gameHwnd = nullptr;

static inline int ClampYaw(int a) {
    while (a > UR180 * 2) a -= UR180 * 2;
    while (a < 0) a += UR180 * 2;
    return a;
}
static inline int ClampPitch(int a) { return a > 16000 ? 16000 : (a < -16000 ? -16000 : a); }

static inline FRotator VecToRot(FVector v) {
    FRotator r;
    r.Yaw = (int)(atan2f(v.Y, v.X) * RAD2UR);
    r.Pitch = (int)(atan2f(v.Z, sqrtf(v.X * v.X + v.Y * v.Y)) * RAD2UR);
    r.Roll = 0;
    return r;
}
static inline FVector RotToVec(FRotator r) {
    float y = r.Yaw * UR2RAD, p = r.Pitch * UR2RAD, cp = cosf(p);
    return FVector(cosf(y) * cp, sinf(y) * cp, sinf(p));
}
static void GetAxes(FRotator r, FVector& X, FVector& Y, FVector& Z) {
    X = RotToVec(r);
    FRotator r2 = r; r2.Yaw += 16384; r2.Pitch = 0; Y = RotToVec(r2); Y.Z = 0.f;
    FRotator r3 = r; r3.Pitch += 16384; Z = RotToVec(r3);
}
static bool W2S(FVector t, Vec2& o, FRotator rot, FVector cam, float fov) {
    FVector ax, ay, az; GetAxes(rot, ax, ay, az);
    FVector d = t - cam;
    float tx = d.X * ay.X + d.Y * ay.Y + d.Z * ay.Z;
    float ty = d.X * az.X + d.Y * az.Y + d.Z * az.Z;
    float tz = d.X * ax.X + d.Y * ax.Y + d.Z * ax.Z;
    if (tz < 1.f) tz = 1.f;
    float s = cx / tanf(fov * PIF / 360.f);
    o.x = cx + tx * s / tz;
    o.y = cy - ty * s / tz;
    return o.x >= 0 && o.x <= scrW && o.y >= 0 && o.y <= scrH;
}

static void DoAim(APlayerController ctrl, ACamera cam, APawn self, APawn tgt) {
    FVector loc = GetLoc(tgt);
    if (cPred) {
        float sp = GetProjSpeed(GetWeapon(self));
        if (sp > 1.f) {
            FVector v = GetVel(tgt);
            float t = (loc - GetCamLoc(cam)).Size() / sp;
            loc.X += v.X * t; loc.Y += v.Y * t;
        }
    }
    loc.Z += GetEye(tgt);
    FRotator want = VecToRot(loc - GetCamLoc(cam));
    want.Yaw = ClampYaw(want.Yaw); want.Pitch = ClampPitch(want.Pitch);
    FRotator cur = GetRot(ctrl); cur.Roll = 0;
    int dy = want.Yaw - cur.Yaw;
    if (dy > UR180) dy -= UR180 * 2;
    if (dy < -UR180) dy += UR180 * 2;
    int dp = want.Pitch - cur.Pitch;
    FRotator out;
    out.Yaw = ClampYaw(cur.Yaw + (int)(dy * cSmooth));
    out.Pitch = ClampPitch(cur.Pitch + (int)(dp * cSmooth));
    out.Roll = 0;
    SetRot(ctrl, out);
}

static BOOL CALLBACK EnumProc(HWND h, LPARAM lp) {
    DWORD pid = 0; GetWindowThreadProcessId(h, &pid);
    if (pid == (DWORD)lp && IsWindowVisible(h)) { gameHwnd = h; return FALSE; }
    return TRUE;
}

static void Tick() {
    static int tickCount = 0;
    if ((tickCount++ % 120) == 0) {
        DWORD pid = GetPid(L"Paladins.exe");
        gameHwnd = nullptr;
        if (pid) EnumWindows(EnumProc, (LPARAM)pid);
    }
    if (gameHwnd) {
        RECT rc{};
        if (GetClientRect(gameHwnd, &rc) && rc.right > 0) {
            POINT o{ 0, 0 }; ClientToScreen(gameHwnd, &o);
            scrW = rc.right; scrH = rc.bottom;
            cx = scrW / 2.f; cy = scrH / 2.f;
            ovl.SetBounds(o.x, o.y, scrW, scrH);
        }
    }

    ovl.Begin();

    UEngine eng = GetEngine();               if (!AddrOk(eng.p)) { ovl.End(); return; }
    ULocalPlayer lp = GetLP(eng);            if (!AddrOk(lp.p)) { ovl.End(); return; }
    APlayerController ctrl = GetCtrl(lp);    if (!AddrOk(ctrl.p)) { ovl.End(); return; }
    APawn self = GetPawn(ctrl);              if (!AddrOk(self.p)) { ovl.End(); return; }
    ACamera cam = GetCam(ctrl);              if (!AddrOk(cam.p)) { ovl.End(); return; }
    AWorldInfo wi = GetWI(ctrl);             if (!AddrOk(wi.p)) { ovl.End(); return; }

    float fov = GetDefFov(cam) * GetFovMul(ctrl);
    if (fov < 10.f || fov > 170.f) fov = 90.f;

    FRotator myRot = GetRot(ctrl);
    FVector camLoc = GetCamLoc(cam);
    float now = GetTimeSeconds(wi);
    int myTeam = GetTeamIdx(GetTeam(GetRep(self)));
    bool aiming = cAim && (GetAsyncKeyState(VK_RBUTTON) & 0x8000);

    if (cNoRecoil) {
        ATgDevice w = GetWeapon(self);
        if (AddrOk(w.p)) { NoRecoil(w); NoSpread(w); }
    }

    float best = 999999.f;
    uint64_t bestPawn = 0;

    for (APawn p = GetPawnList(wi); AddrOk(p.p); p = NextPawn(p)) {
        APawn next = NextPawn(p);
        bool last = !AddrOk(next.p);

        int hp = GetHealth(p);
        if (hp < 1 || hp > 10000) { if (last) break; continue; }
        ARepInfo rep = GetRep(p);              if (!AddrOk(rep.p)) { if (last) break; continue; }
        ATeamInfo tm = GetTeam(rep);           if (!AddrOk(tm.p)) { if (last) break; continue; }
        if (GetTeamIdx(tm) == myTeam) { if (last) break; continue; }
        USkeletalMesh mesh = GetMesh(p);       if (!AddrOk(mesh.p)) { if (last) break; continue; }

        FVector loc = GetLoc(p);
        if ((loc - camLoc).Size() > cMaxDist) { if (last) break; continue; }
        bool vis = IsVisible(mesh, now);

        Vec2 foot;
        if (!W2S(loc, foot, myRot, camLoc, fov)) { if (last) break; continue; }

        FBoxSphereBounds b = GetBounds(mesh);
        Vec2 sl, sh;
        bool boxOk = W2S(b.Origin - b.BoxExtent, sl, myRot, camLoc, fov)
                  && W2S(b.Origin + b.BoxExtent, sh, myRot, camLoc, fov);

        D2D1_COLOR_F col = vis ? D2D1::ColorF(0.15f, 1.f, 0.25f) : D2D1::ColorF(1.f, 0.2f, 0.2f);

        if (cTracer) ovl.Line(cx, (float)scrH, foot.x, foot.y, col);

        if (boxOk) {
            float w = fabsf((sh.y - sl.y) / 4.f), top = sh.y, bot = sl.y;
            ovl.Line(foot.x - w, bot, foot.x + w, bot, col);
            ovl.Line(foot.x - w, top, foot.x + w, top, col);
            ovl.Line(foot.x - w, bot, foot.x - w, top, col);
            ovl.Line(foot.x + w, bot, foot.x + w, top, col);

            int mhp = GetMaxHealth(p);
            float pct = mhp > 0 ? (float)hp / (float)mhp : 0.f;
            float hgt = fabsf(bot - top);
            ovl.FillRect(foot.x - w - 6.f, top + hgt * (1.f - pct), foot.x - w - 2.f, top + hgt,
                pct > 0.5f ? D2D1::ColorF(0.2f, 1.f, 0.2f) : D2D1::ColorF(1.f, 0.3f, 0.2f));

            std::wstring n = GetName(rep);
            if (!n.empty()) ovl.Text(foot.x + w + 4.f, top - 2.f, D2D1::ColorF(1.f, 1.f, 0.3f), n.c_str());
        }

        if (aiming && vis) {
            Vec2 head;
            FVector hl = loc; hl.Z += GetEye(p);
            if (W2S(hl, head, myRot, camLoc, fov)) {
                float dx = head.x - cx, dy2 = head.y - cy;
                float cd = sqrtf(dx * dx + dy2 * dy2);
                if (cd < cAimFov * (cx / fov) && cd < best) { best = cd; bestPawn = p.p; }
            }
        }
        if (last) break;
    }

    if (aiming && bestPawn) DoAim(ctrl, cam, self, APawn{ bestPawn });

    ovl.End();
}

int main() {
    SetConsoleTitleW(L"Paladins External");

    DWORD pid = GetPid(L"Paladins.exe");
    if (!pid) { printf("[!] Paladins.exe nao encontrado\n"); system("pause"); return 1; }

    g_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!g_hProc) { printf("[!] OpenProcess falhou (%lu) - rode como admin\n", GetLastError()); system("pause"); return 1; }

    g_Base = GetModuleBase(pid, L"Paladins.exe");
    if (!g_Base) { printf("[!] base do modulo falhou\n"); system("pause"); return 1; }
    if (RPM<IMAGE_DOS_HEADER>(g_Base).e_magic != 0x5A4D) { printf("[!] header invalido\n"); system("pause"); return 1; }

    if (!ResolveEngine()) { printf("[!] UEngine nao resolvido - offsets velhos\n"); system("pause"); return 1; }
    printf("[+] engine: 0x%llX\n", g_EnginePtrAddr);

    if (!ovl.Init()) { printf("[!] overlay falhou\n"); system("pause"); return 1; }

    while (!(GetAsyncKeyState(VK_INSERT) & 0x8000)) {
        if (GetAsyncKeyState(VK_F1) & 0x8000) { cEsp = !cEsp; Sleep(150); }
        if (GetAsyncKeyState(VK_F2) & 0x8000) { cAim = !cAim; Sleep(150); }
        if (GetAsyncKeyState(VK_F3) & 0x8000) { cTracer = !cTracer; Sleep(150); }
        if (cEsp) Tick(); else { ovl.Begin(); ovl.End(); }
        Sleep(1);
    }
    return 0;
}
