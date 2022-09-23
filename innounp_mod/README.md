```
\------------------------------------------------------------------------------/
|   __________         __         .__                     __                   |
|   \______   \_____ _/  |_  ____ |  |__     ____   _____/  |_  ____   ______  |
|    |     ___/\__  \\   __\/ ___\|  |  \   /    \ /  _ \   __\/ __ \ /  ___/  |
|    |    |     / __ \|  | \  \___|   Y  \ |   |  (  <_> )  | \  ___/ \___ \   |
|    |____|    (____  /__|  \___  >___|  / |___|  /\____/|__|  \___  >____  >  |
|                   \/          \/     \/       \/                 \/     \/   |
|   Innounp v50                                                                |
/------------------------------------------------------------------------------\

Note;
innounp mod, unpack encrypted setup embedded files with -m switch 
to extract embeddeded setup header part IFPS (CompiledCode.bin).

Step 1#
CFF(ntcore)>Nt Headers>Optinal Header>DllCharacteristics>Uncheck DLL can move (remove ALSR!)

# 1. Always overwrite existing files, don't prompt
src: innounp.dpr#L587
	Result := (OverwriteAction = oaOverwrite);
	if (OverwriteAction <> oaAsk) then Exit;
 Assemble:
00495EF0 | 803D 8C224A00 02     | cmp byte ptr ds:[4A228C],2                                 |
 to
00495EF0 | 803D 8C224A00 00     | cmp byte ptr ds:[4A228C],0                                 |

# 2. Cncrypted file chunk found, prompt for CryptKey. Don't prompt, skip.
src: innounp.dpr#L610
	change foChunkEncrypted flag
	if (InteractiveMode) and (foChunkEncrypted in CurFileLocation^.Flags) and (FileExtractor.CryptKey = '') then#L632
 Assemble:
0049612A | 83BE 30010000 00     | cmp dword ptr ds:[esi+130],0                               |
 to
0049612A | 83BE 30010000 01     | cmp dword ptr ds:[esi+130],1                               |

# 3. Decompress ftFakeFile
src: innounp.dpr#L656 { Decompress a file }
	if CurFile^.FileType<>ftFakeFile then begin
 Assemble:
00496228 | 74 22                | je innounp_v50.49624C                                      |
 to
00496228 | EB 22                | jmp innounp_v50.49624C                                     |

# It's not a bug but a feature
- Extracts all filesnames, structure and hierarchy, but all encrypted chucks are never written (empty skeleton).


```
