# MemoryManager

MemoryManager, Windows işletim sistemi üzerinde çalışan işlemlerle etkileşim kurarak bellek yönetimi yapmanıza olanak sağlayan bir C++ sınıfıdır. İşlem ID'si bulmaktan bellek okuma/yazmaya, modül taban adreslerini bulmaktan bellek koruma seviyelerini değiştirmeye kadar pek çok işlevi kolayca gerçekleştirebilirsiniz.

## Özellikler

### İşlem ID'sini Bulma
Bir işlem adını kullanarak, o işlemin ID'sini alabilirsiniz. Eğer işlem bulunamazsa ya da bir hata oluşursa, uygun hata mesajlarını göreceksiniz.

```cpp
DWORD GetProcessIdByName(const std::wstring& processName);
```

### İşlem Handle'ı Almak
Bir işlem ID'si üzerinden, o işlem ile etkileşim kurabileceğiniz bir handle alabilirsiniz. Eğer işlem açılamazsa hata mesajıyla karşılaşırsınız.

```cpp
HANDLE GetProcessHandle(DWORD processId);
```

### Bellek Okuma ve Yazma
Bir işlemden veri okumak ya da yazmak oldukça basit. Örneğin, bir adresin içeriğini okuyabilir veya istediğiniz değeri yazabilirsiniz.

```cpp
template <typename T>
T ReadMemory(HANDLE processHandle, uintptr_t address);

template <typename T>
bool WriteMemory(HANDLE processHandle, uintptr_t address, T value);
```

### Modül Taban Adresini Bulmak
Bir işlemdeki belirli bir DLL ya da modülün taban adresini bulabilirsiniz.

```cpp
uintptr_t GetModuleBaseAddress(DWORD processId, const std::wstring& moduleName);
```

### String Okuma
Bir bellek adresindeki string değerini okuyabilirsiniz. Örneğin, bir karakter dizisi ya da uygulama içindeki metinlere kolaylıkla erişebilirsiniz.

```cpp
std::string ReadString(HANDLE processHandle, uintptr_t address, size_t maxLength = 256);
```

### DMA Adresi Bulma
Dinamik bellek adreslerini çözmek için bir temel adres ve ofsetler kümesi sağlayarak, nihai adresi bulabilirsiniz.

```cpp
uintptr_t FindDMAAddy(HANDLE processHandle, uintptr_t baseAddress, const std::vector<uintptr_t>& offsets);
```

### Bellek Koruma Seviyelerini Yönetme
Bir bellek bölgesinin koruma seviyesini değiştirebilir ve eski koruma seviyesini geri yükleyebilirsiniz.

```cpp
bool ProtectMemory(HANDLE processHandle, uintptr_t address, size_t size, DWORD newProtect, DWORD& oldProtect);

bool RestoreMemoryProtection(HANDLE processHandle, uintptr_t address, size_t size, DWORD oldProtect);
```
