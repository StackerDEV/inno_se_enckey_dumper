v.50
>innounp_v50.exe
00095EF6:02->00
00096130:00->01
00096228:74->EB

v.49
>innounp_v49.exe
00094BA6:02->00
00094DE0:00->01
00094ED8:74->EB


00094BA6:02->00
always overwrite existing files, don't prompt

00094DE0:00->01
encrypted file chunk found, prompt for CryptKey. Don't prompt, skip.

00094ED8:74->EB
never initialize encrypted file extractor.. Decompress ftFakeFile