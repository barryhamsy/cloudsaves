#define MyAppName "AltSteamCloudSaves"
#define MyAppVersion "1.0"
#define MyAppPublisher "AltSteamCloudSaves"
#define MyAppExeName "AltSteamCloudSaves.exe"

[Setup]
AppId={{8A9C2F13-7E84-4FD2-BAC7-9E71E36D3D0B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
; Require admin privileges for installation
PrivilegesRequired=admin
; Force all users installation (requires admin)
PrivilegesRequiredOverridesAllowed=commandline
OutputDir=D:\github_cloud_backup_app\AltSteamCloudSaves
OutputBaseFilename=AltSteamCloudSaves_1.0.1
SetupIconFile=D:\github_cloud_backup_app\cloudsaves.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Add manifest to request admin execution
SetupMutex=Global\{#MyAppName}_Setup_Mutex

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "runasadmin"; Description: "Always run as administrator"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkablealone checkedonce


[Files]
Source: "D:\github_cloud_backup_app\app.dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\github_cloud_backup_app\app.dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon runasadmin


[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; \
  Description: "Installing WebView2 Kit..."; \
  Flags: waituntilterminated shellexec runhidden; \
  Parameters: "/silent /install"; \
  StatusMsg: "This will take more than a minutes depending on your internet speed..Installing WebView2 Kit..."

[Code]
function NeedsWebView2Runtime(): Boolean;
var
  key: string;
begin
  key := 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F1E7EE4F-3D83-4094-BC4F-6A37A54DEBA9}';
  Result := not RegKeyExists(HKEY_LOCAL_MACHINE, key);
end;
