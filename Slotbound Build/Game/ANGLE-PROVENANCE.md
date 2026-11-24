# Windows ANGLE runtime provenance

SlotBound uses these two x64 ANGLE libraries to translate LÖVE's OpenGL ES
renderer to Direct3D 11 on Windows. They were extracted without modification
from the official Electron v42.7.1 Windows x64 release.

- Release: https://github.com/electron/electron/releases/tag/v42.7.1
- Archive: `electron-v42.7.1-win32-x64.zip`
- Archive SHA-256: `2328058C825548541059D421F7DEB7DED3AD281AE1B93BCD7CBB6D2E161A950C`
- Official checksums: https://github.com/electron/electron/releases/download/v42.7.1/SHASUMS256.txt
- `libEGL.dll` SHA-256: `12F7BA4068BCCEBB3B7AC555CB24786E8CCD9F1CD82DB7C1AB383C78EEA7C1B9`
- `libGLESv2.dll` SHA-256: `9742602E6CEDB6343D8F3484C0575D650D07066A8D71D001BD6B1AF7646E8CF4`
- Reported ANGLE version: `2.1.27535`, commit `7281658d271e`

The pair was verified with LÖVE 11.5 r2 as `OpenGL ES 3.0`, renderer `ANGLE`,
backend `Direct3D11`, on the full SlotBound main menu and shader set. Do not
replace only one DLL: the two files are a versioned pair and the runtime checks
pin both hashes.

`ANGLE-LICENSE.txt` contains ANGLE's BSD license.
`ANGLE-ELECTRON-LICENSE.txt` is Electron's accompanying MIT license.
`ANGLE-THIRD-PARTY-NOTICES.html` is the unmodified Chromium notice bundle from
the same verified archive.
