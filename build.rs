use std::path::PathBuf;

fn main() {
    let cfg = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/main.slint", cfg).expect("slint build failed");
    println!("cargo:rerun-if-changed=assets");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        windows_resources();
    }
}

/// Icon, manifest (DPI awareness, common controls v6, asInvoker) and version info.
fn windows_resources() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut nums: Vec<u32> = ver.split(['.', '-']).filter_map(|x| x.parse().ok()).collect();
    nums.resize(4, 0);
    let (a, b, c, d) = (nums[0], nums[1], nums[2], nums[3]);
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity type="win32" name="Lazeyka" version="{a}.{b}.{c}.{d}" processorArchitecture="amd64"/>
  <description>Lazeyka VPN</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
    </application>
  </compatibility>
  <asmv3:application>
    <asmv3:windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"#
    );
    let man_path = out.join("lazeyka.manifest");
    std::fs::write(&man_path, manifest).unwrap();
    let icon = root.join("assets").join("lazeyka.ico");
    let slash = |p: &PathBuf| p.display().to_string().replace('\\', "/");
    let rc = format!(
        r#"#pragma code_page(65001)
1 ICON "{icon}"
1 24 "{man}"
1 VERSIONINFO
FILEVERSION {a},{b},{c},{d}
PRODUCTVERSION {a},{b},{c},{d}
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "041904B0"
    BEGIN
      VALUE "CompanyName", "Лазейка"
      VALUE "FileDescription", "Лазейка — VPN-клиент"
      VALUE "FileVersion", "{ver}"
      VALUE "InternalName", "lazeyka"
      VALUE "LegalCopyright", "GPL-3.0-or-later"
      VALUE "OriginalFilename", "lazeyka.exe"
      VALUE "ProductName", "Лазейка"
      VALUE "ProductVersion", "{ver}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x419, 1200
  END
END
"#,
        icon = slash(&icon),
        man = slash(&man_path)
    );
    let rc_path = out.join("lazeyka.rc");
    std::fs::write(&rc_path, rc).unwrap();
    let obj = out.join("lazeyka-res.o");
    let windres = std::env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".into());
    // llvm-windres ignores "#pragma code_page": without -c the UTF-8 strings of the version
    // info are read as cp1252 and Task Manager shows mojibake
    let st = std::process::Command::new(&windres).args(["-c", "65001"]).arg("-i").arg(&rc_path).arg("-o").arg(&obj).args(["-O", "coff"]).status();
    match st {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg-bins={}", obj.display()),
        other => println!("cargo:warning=Windows resources skipped ({windres}: {other:?})"),
    }
}
