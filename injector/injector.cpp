#include <windows.h>
#include <iostream>
#include <exception>
#include <string>

using namespace std;

ULONG32 PEAlign(ULONG32 dwNumber, ULONG32 dwAlign)
{
    return(((dwNumber + dwAlign - 1) / dwAlign) * dwAlign);
}

BOOL AddNewSection(const string& strTargetFile, ULONG ulNewSectionSize)
{
    BOOL bOk = FALSE;
    HANDLE TargetFileHandle = nullptr;
    HANDLE MappingHandle = nullptr;
    PVOID FileData = nullptr;
    ULONG ulFileSize = 0;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pNewSectionHeader = NULL;
    PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
    DWORD FileSize = 0;
    DWORD FileOffset = 0;
    DWORD VirtualSize = 0;
    DWORD VirtualOffset = 0;
    PCHAR pNewSectionContent = NULL;
    DWORD dwWrittenLength = 0;

    // 打开文件
    TargetFileHandle = CreateFileA(strTargetFile.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (TargetFileHandle == INVALID_HANDLE_VALUE)
    {
        goto EXIT;
    }

    ulFileSize = GetFileSize(TargetFileHandle, NULL);
    if (INVALID_FILE_SIZE == ulFileSize)
    {
        goto EXIT;
    }

    // 映射文件
    MappingHandle = CreateFileMappingA(TargetFileHandle, NULL, PAGE_READWRITE, 0, ulFileSize, NULL);
    if (MappingHandle == NULL)
    {
        goto EXIT;
    }

    // 得到缓存头
    FileData = MapViewOfFile(MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, ulFileSize);
    if (FileData == NULL)
    {
        goto EXIT;
    }

    // 判断是否是PE文件
    if (((PIMAGE_DOS_HEADER)FileData)->e_magic != IMAGE_DOS_SIGNATURE)
    {
        goto EXIT;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)FileData + ((PIMAGE_DOS_HEADER)FileData)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        goto EXIT;
    }

    // 判断是否可以增加一个新节
    if ((pNtHeaders->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER) > pNtHeaders->OptionalHeader.SizeOfHeaders)
    {
        goto EXIT;
    }

    // 得到新节的起始地址， 最后的起始地址
    pNewSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1) + pNtHeaders->FileHeader.NumberOfSections;
    pLastSectionHeader = pNewSectionHeader - 1;

    // 对齐RVA和偏移
    FileSize = PEAlign(ulNewSectionSize, pNtHeaders->OptionalHeader.FileAlignment);
    FileOffset = PEAlign(pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData, pNtHeaders->OptionalHeader.FileAlignment);
    VirtualSize = PEAlign(ulNewSectionSize, pNtHeaders->OptionalHeader.SectionAlignment);
    VirtualOffset = PEAlign(pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize, pNtHeaders->OptionalHeader.SectionAlignment);

    // 填充新节表
    memcpy(pNewSectionHeader->Name, "Inject", strlen("Inject"));
    pNewSectionHeader->VirtualAddress = VirtualOffset;
    pNewSectionHeader->Misc.VirtualSize = VirtualSize;
    pNewSectionHeader->PointerToRawData = FileOffset;
    pNewSectionHeader->SizeOfRawData = FileSize;
    pNewSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // 修改IMAGE_NT_HEADERS
    pNtHeaders->FileHeader.NumberOfSections++;
    pNtHeaders->OptionalHeader.SizeOfImage += VirtualSize;
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;

    // 添加新节到文件尾部
    SetFilePointer(TargetFileHandle, 0, 0, FILE_END);
    pNewSectionContent = new CHAR[FileSize];
    RtlZeroMemory(pNewSectionContent, FileSize);
    dwWrittenLength = 0;
    if (!WriteFile(TargetFileHandle, pNewSectionContent, FileSize, &dwWrittenLength, nullptr))
    {
        goto EXIT;
    }

    bOk = TRUE;
EXIT:
    if (TargetFileHandle != NULL)
    {
        CloseHandle(TargetFileHandle);
        TargetFileHandle = nullptr;
    }
    if (FileData != NULL)
    {
        UnmapViewOfFile(FileData);
        FileData = nullptr;
    }
    if (MappingHandle != NULL)
    {
        CloseHandle(MappingHandle);
        MappingHandle = nullptr;
    }
    return bOk;
}

PIMAGE_SECTION_HEADER GetOwnerSection(PIMAGE_NT_HEADERS pNTHeaders, DWORD dwRVA)
{
    int i;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pNTHeaders + 1);
    for (i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++)
    {
        if ((dwRVA >= (pSectionHeader + i)->VirtualAddress) && (dwRVA <= ((pSectionHeader + i)->VirtualAddress + (pSectionHeader + i)->SizeOfRawData)))
        {
            return ((PIMAGE_SECTION_HEADER)(pSectionHeader + i));
        }
    }
    return PIMAGE_SECTION_HEADER(NULL);
}

DWORD RVAToFOA(PIMAGE_NT_HEADERS pNTHeaders, DWORD dwRVA)
{
    DWORD _offset;
    PIMAGE_SECTION_HEADER section;

    // 找到偏移所在节
    section = GetOwnerSection(pNTHeaders, dwRVA);
    if (section == NULL)
    {
        return(0);
    }

    // 修正偏移
    _offset = dwRVA + section->PointerToRawData - section->VirtualAddress;

    return(_offset);
}

BOOL AddNewImportDescriptor(const string& strTargetFile, const string& strInjectDllName, const string& strFunctionName)
{
    BOOL bOk = FALSE;
    ULONG ulFileSize = 0;
    HANDLE TargetFileHandle = nullptr;
    HANDLE MappingHandle = nullptr;
    PVOID FileData = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pImportTable = nullptr;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    BOOL  bBoundImport = FALSE;
    PIMAGE_SECTION_HEADER pNewSectionHeader = NULL;
    PBYTE pNewSectionData = NULL;
    PBYTE pNewImportDescriptor = NULL;
    INT i = 0;
    DWORD dwDelt = 0;
    PIMAGE_THUNK_DATA pNewThunkData = NULL;
    PBYTE pszDllName = NULL;
    PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

    // 打开文件
    TargetFileHandle = CreateFileA(strTargetFile.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (TargetFileHandle == INVALID_HANDLE_VALUE)
    {
        goto EXIT;
    }

    ulFileSize = GetFileSize(TargetFileHandle, NULL);
    if (INVALID_FILE_SIZE == ulFileSize)
    {
        goto EXIT;
    }

    // 映射文件
    MappingHandle = CreateFileMappingA(TargetFileHandle, NULL, PAGE_READWRITE, 0, ulFileSize, NULL);
    if (MappingHandle == NULL)
    {
        goto EXIT;
    }

    // 得到缓存头
    FileData = MapViewOfFile(MappingHandle, FILE_MAP_ALL_ACCESS, 0, 0, ulFileSize);
    if (FileData == NULL)
    {
        goto EXIT;
    }

    // 判断是否是PE文件
    if (((PIMAGE_DOS_HEADER)FileData)->e_magic != IMAGE_DOS_SIGNATURE)
    {
        goto EXIT;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)FileData + ((PIMAGE_DOS_HEADER)FileData)->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        goto EXIT;
    }

    // 得到原导入表
    pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)FileData + RVAToFOA(pNtHeaders, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));

    // 判断是否使用了绑定导入表
    if (pImportTable->Characteristics == 0 && pImportTable->FirstThunk != 0)
    {
        bBoundImport = TRUE;
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    }

    // 找到自己添加的新节
    pNewSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1) + pNtHeaders->FileHeader.NumberOfSections - 1;
    pNewSectionData = pNewSectionHeader->PointerToRawData + (PBYTE)FileData;
    pNewImportDescriptor = pNewSectionData;

    // 往新节中拷贝原导入表内容
    i = 0;
    while (pImportTable->FirstThunk != 0 || pImportTable->Characteristics != 0)
    {
        memcpy(pNewSectionData + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), pImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        pImportTable++;
        pNewImportDescriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        i++;
    }

    // 复制最后一个描述符
    memcpy(pNewImportDescriptor, pNewImportDescriptor - sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(IMAGE_IMPORT_DESCRIPTOR));

    // 计算修正值
    dwDelt = pNewSectionHeader->VirtualAddress - pNewSectionHeader->PointerToRawData;

    // pNewImportDescriptor 当前指向要构造的新描述符 再空出一个空描述符作为导入表的结束符 所以是 2 *
    pNewThunkData = PIMAGE_THUNK_DATA(pNewImportDescriptor + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    pszDllName = (PBYTE)(pNewThunkData + 2);
    memcpy(pszDllName, strInjectDllName.c_str(), strInjectDllName.length());

    // 确定 DllName 的位置
    pszDllName[strInjectDllName.length() + 1] = 0;

    // 确定 IMAGE_IMPORT_BY_NAM 的位置
    pImportByName = (PIMAGE_IMPORT_BY_NAME)(pszDllName + strInjectDllName.length() + 1);

    // 初始化 IMAGE_THUNK_DATA
    pNewThunkData->u1.Ordinal = (DWORD_PTR)pImportByName - (DWORD_PTR)FileData + /*加上修正值 - 这里应该填充在内存中的地址*/dwDelt;

    // 初始化 IMAGE_IMPORT_BY_NAME
    pImportByName->Hint = 1;
    memcpy(pImportByName->Name, strFunctionName.c_str(), strFunctionName.length());
    pImportByName->Name[strFunctionName.length() + 1] = 0;

    // 初始化 PIMAGE_IMPORT_DESCRIPTOR
    if (bBoundImport)
    {
        ((PIMAGE_IMPORT_DESCRIPTOR)pNewImportDescriptor)->OriginalFirstThunk = 0;
    }
    else
    {
        ((PIMAGE_IMPORT_DESCRIPTOR)pNewImportDescriptor)->OriginalFirstThunk = dwDelt + (DWORD_PTR)pNewThunkData - (DWORD_PTR)FileData;
    }
    ((PIMAGE_IMPORT_DESCRIPTOR)pNewImportDescriptor)->FirstThunk = dwDelt + (DWORD_PTR)pNewThunkData - (DWORD_PTR)FileData;
    ((PIMAGE_IMPORT_DESCRIPTOR)pNewImportDescriptor)->Name = dwDelt + (DWORD_PTR)pszDllName - (DWORD_PTR)FileData;

    // 修改导入表入口
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pNewSectionHeader->VirtualAddress;
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    bOk = TRUE;
EXIT:
    if (TargetFileHandle != NULL)
    {
        CloseHandle(TargetFileHandle);
        TargetFileHandle = nullptr;
    }

    if (FileData != NULL)
    {
        UnmapViewOfFile(FileData);
        FileData = nullptr;
    }

    if (MappingHandle != NULL)
    {
        CloseHandle(MappingHandle);
        MappingHandle = nullptr;
    }
    return bOk;
}

BOOL AddImportTable(const string& strTargetFile, const string& strInjectDllName, const string& strFunctionName)
{
    BOOL bOk = FALSE;

    if (!AddNewSection(strTargetFile, 256))
    {
        goto end;
    }

    if (!AddNewImportDescriptor(strTargetFile, strInjectDllName, strFunctionName))
    {
        goto end;
    }

    bOk = TRUE;
end:
    return bOk;
}


int main(int argc, char* argv[])
{
    const char* processName = nullptr;
    const char* moduleName = nullptr;
    const char* exportFunctionName = nullptr;

    for (int i = 1; i < argc; i += 2) {
        if (i + 1 < argc) {
            if (std::string(argv[i]) == "-f") {
                processName = argv[i + 1];
            }
            else if (std::string(argv[i]) == "-x") {
                moduleName = argv[i + 1];
            }
            else if (std::string(argv[i]) == "-i") {
                exportFunctionName = argv[i + 1];
            }
            else if (std::string(argv[i]) == "-h") {
                std::cout << "Usage: -f <process_name> -x <module_name> -i <export_function_name> -h (for help)" << std::endl;
                return 0;
            }
            else {
                std::cout << "Invalid option: " << argv[i] << std::endl;
                std::cout << "Usage: -f <process_name> -x <module_name> -i <export_function_name> -h (for help)" << std::endl;
                return 1;
            }
        }
        else {
            std::cout << "Incomplete option: " << argv[i] << std::endl;
            std::cout << "Usage: -f <process_name> -x <module_name> -i <export_function_name> -h (for help)" << std::endl;
            return 1;
        }
    }

    if (processName && moduleName && exportFunctionName) {
        AddImportTable(processName, moduleName, exportFunctionName);
    }
    else {
        std::cout << "Missing required options. Use -h for help." << std::endl;
        return 1;
    }

    system("pause");
    return 0;
}

