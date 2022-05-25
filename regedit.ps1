function reg-key-edit{
Param ($key, $name, $unused1, $value)
if (!(Test-Path $key)){ New-Item -Path $key -Force }
New-ItemProperty -Path $key -Name $name -Value $value -Force
}

#reg-key-edit "HKLM:\Software\bigballs" "abc" 43



#SMB
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" "REG_DWORD" "4"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" "REG_DWORD" "0"


#SMB Packet Signing Enabled
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature" "REG_DWORD" "1"

#RDP Stuff
#Disables
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm" "REG_DWORD" "1"
#Disables
reg add "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
#Enables
reg add "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

#Misc
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut" "REG_SZ" "600"
reg-key-edit "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut" "REG_SZ" "600"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" "REG_SZ" "1"
reg-key-edit "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure" "REG_SZ" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableSmartScreen" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" "REG_SZ" "Block"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM" "REG_SZ" "O:SYG:SYD:(A;;RC;;;BA)"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes" "REG_DWORD" "2147483640"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u" "AllowOnlineID" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" "allownullsessionfallback" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" "REG_DWORD" "5"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application" "MaxSize" "REG_DWORD" "32768"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\System" "EnumerateLocalUsers" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security" "MaxSize" "REG_DWORD" "1024000"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System" "MaxSize" "REG_DWORD" "32768"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge" "REG_DWORD" "30"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel" "REG_DWORD" "3"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" "AllowBasicAuthInClear" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Installer" "EnableUserControl" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Installer" "SafeForScripting" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting" "REG_DWORD" "2"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIpSourceRouting" "REG_DWORD" "2"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" "NoNameReleaseOnDemand" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" "FormSuggest Passwords" "REG_SZ" "no"
reg-key-edit "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings" "PreventCertErrorOverrides" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "PreventOverrideAppRepUnknown" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "PreventOverride" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\PassportForWork\PINComplexity" "MinimumPINLength" "REG_DWORD" "6"
reg-key-edit "HKLM:\Software\Policies\Microsoft\PassportForWork" "RequireSecurityDevice" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "EnabledV9" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" "DisableInventory" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\System" "AllowDomainPINLogon" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" "UseLogonCredential" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec" "REG_DWORD" "537395200"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec" "REG_DWORD" "537395200"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoReadingPane" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPreviewPane" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoReadingPane" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPreviewPane" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" "REG_DWORD" "2"
reg-key-edit "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy" "REG_DWORD" "3"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "REG_DWORD" "2"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" "Enabled" "REG_DWORD" "1"
#reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" "EccCurves" "REG_MULTI_SZ" "NistP384 NistP256"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Classes\batfile\shell\runasuser" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKLM:\Software\Classes\cmdfile\shell\runasuser" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKLM:\Software\Classes\exefile\shell\runasuser" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKLM:\Software\Classes\mscfile\shell\runasuser" "SuppressionPolicy" "REG_DWORD" "4096"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" "REG_DWORD" "600"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText" "REG_SZ" "This is a logon banner. Ben, if you are seeing this, Adam is better. Let's win this bois. ggez."
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption" "REG_SZ" "EHS Cyber Knights"
reg-key-edit "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "REG_SZ" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock" "REG_DWORD" "2"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoice" "REG_DWORD" "2"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer" "NoDriveTypeAutoRun" "REG_DWORD" "255"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "AutoInstallMinorUpdates" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" "AUOptions" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "DisableWindowsUpdateAccess" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "ElevateNonAdmins" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\Internet Communication Management\Internet Communication" "DisableWindowsUpdateAccess" "REG_DWORD" "0"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWindowsUpdate" "REG_DWORD" "0"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" "DisableWindowsUpdateAccess" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateCDRoms" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateFloppies" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "ClearPageFileAtShutdown" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" "AuditLevel" "REG_DWORD" "8"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "auditbaseobjects" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "fullprivilegeauditing" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "restrictanonymous" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "disabledomaincreds" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "everyoneincludesanonymous" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "dontdisplaylastusername" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "undockwithoutlogon" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "autodisconnect" "REG_DWORD" "45"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "enablesecuritysignature" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "requiresecuritysignature" "REG_DWORD" "0"
##reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "NullSessionPipes" "REG_MULTI_SZ" """"
##reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" "NullSessionShares" "REG_MULTI_SZ" """"
##reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" "Machine" "REG_MULTI_SZ" """"
##reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" "Machine" "REG_MULTI_SZ" """"
reg-key-edit "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "EnabledV8" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "DisablePasswordCaching" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "DisablePasswordCaching" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnonBadCertRecving" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnonBadCertRecving" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnOnPostRedirect" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "WarnOnPostRedirect" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" "REG_DWORD" "1"
reg-key-edit "HKCU:\.DEFAULT\Control Panel\Accessibility\StickyKeys" "Flags" "REG_SZ" "506"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSuperHidden" "REG_DWORD" "1"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" "CrashDumpEnabled" "REG_DWORD" "0"
reg-key-edit "HKCU:\SYSTEM\CurrentControlSet\Control\CrashControl" "CrashDumpEnabled" "REG_DWORD" "0"
reg-key-edit "HKLM:\SYSTEM\CurrentControlSet\Services\CDROM" "AutoRun" "REG_DWORD" "1"
reg-key-edit "HKCU:\SYSTEM\CurrentControlSet\Services\CDROM" "AutoRun" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun" "REG_DWORD" "255"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\access\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\access\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\excel\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\excel\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\excel\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\excel\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\excel\security" "excelbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\excel\security" "excelbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\ms project\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\ms project\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\ms project\security" "level" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\ms project\security" "level" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\outlook\security" "level" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\outlook\security" "level" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\powerpoint\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\powerpoint\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\powerpoint\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\powerpoint\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\publisher\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\publisher\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\visio\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\visio\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\visio\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\visio\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\word\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\word\security" "vbawarnings" "REG_DWORD" "4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\word\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\word\security" "blockcontentexecutionfrominternet" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\16.0\word\security" "wordbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\16.0\word\security" "wordbypassencryptedmacroscan" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\office\common\security" "automationsecurity" "REG_DWORD" "3"
reg-key-edit "HKCU:\Software\Policies\Microsoft\office\common\security" "automationsecurity" "REG_DWORD" "3"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows Defender" "ServiceKeepAlive" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "CheckForSignaturesBeforeRunningScan" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "DisableHeuristics" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus" "REG_DWORD" "3"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "VLimitEnhancedDiagnosticDataWindowsAnalytics" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "QueryNetBTFQDN" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "NameServer" "REG_SZ" "8.8.8.8 8.8.4.4"
reg-key-edit "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "RegistrationTtl" "REG_DWORD" "600"
reg-key-edit "HKLM:\Software\policies\Microsoft\Peernet" "IgnoreDomainPasswordPolicyForNewGroups" "REG_DWORD" "0"
#Printer-
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" "Enabled" "REG_DWORD" "0"
#RDP- only comment out if you lose points
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" "Enabled" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" "Enabled" "REG_DWORD" "0"
#UPnP-disable unsolicited
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" "Enabled" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\GloballyOpenPorts" "AllowUserPrefMerge" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogDroppedPackets" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogSuccessfulConnections" "REG_DWORD" "1"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogFilePath" "REG_SZ" "	%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" "LogFileSize" "REG_DWORD" "4096"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile\GloballyOpenPorts" "Enabled" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" "DisableNotifications" "REG_DWORD" "0"
reg-key-edit "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" "EnableFirewall" "REG_DWORD" "1"