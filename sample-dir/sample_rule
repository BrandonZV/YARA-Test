rule MemoryModule {
    meta:
	id = "6O9mUMvPhziJ72IXHf6muZ"
	fingerprint = "4aa0a23f28698898404d700cb363ddf06dd275f5798815e797113656a2a40ae8"
	version = "1.0"
	first_imported = "2020-05-06"
	last_modified = "2020-05-06"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "CCCS"
	author = "analyst@CCCS"
	description = "Yara rule to detect usage of MemoryModule Library"
	category = "TECHNIQUE"
	technique = "LOADER:MEMORYMODULE"
	mitre_att = "T1129"
	report = "TA20-0192"
	hash = "812bbe8b9acabad05b08add50ee55c883e1f7998f3a7cae273d3f0d572a79adc"

    strings:
        $func_ptr =    {55 8B EC 6A 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00}
        $func_ptr_64 = {48 [3] 48 [4] 00 00 00 00 48 8? [5] 48 8? [3] 4? 8? [5] 48 8? [3-5] 48 8?}
        $api_1 = "LoadLibraryA"
        $api_2 = "GetProcAddress"
        $api_3 = "FreeLibrary"
        $api_4 = "VirtualFree"
        $api_5 = "VirtualProtect"
        $api_6 = "VirtualAlloc"

    condition:
        uint16(0) == 0x5a4d and all of ($api*) and ($func_ptr or $func_ptr_64)
}
