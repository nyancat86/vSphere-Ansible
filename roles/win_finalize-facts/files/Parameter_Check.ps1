###############################################
# Windows Server OS パラメータチェックツール  #
###############################################
$Path = ".\"
$hostname = hostname
$DATE = Get-Date -Format "yyyyMMdd"
$DATE_OUTPUT = Get-Date -Format "yyyy/MM/dd HH:mm:ss"

echo "########## 確認対象 ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt
echo "ホスト名 : $hostname" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "取得日時 : $DATE_OUTPUT" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## 確認対象基本情報 ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'systeminfo' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## 基本設定 ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** OS名/Edition/Service Pack ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
(Get-WmiObject Win32_OperatingSystem).Caption | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ライセンス認証 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cscript "C:\Windows\System32\slmgr.vbs" /dli | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** コンピュータ名 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
(Get-CimInstance -Class Win32_ComputerSystem).Name | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** CPU ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$PhysicalSockets=(Get-WmiObject Win32_ComputerSystem).NumberOfProcessors
echo "ソケット数 : $PhysicalSockets" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

$PhysicalCores = 0
(Get-WmiObject Win32_Processor).NumberOfCores | %{ $PhysicalCores += $_}
echo "コア数     : $PhysicalCores" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** メモリ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Class Win32_PhysicalMemory |%{ $_.Capacity}| Measure-Object -Sum | %{ ($_.sum /1024/1024/1024).toString()+"GB"}| Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ドライブ構成1(容量/パーティションのスタイル) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-Disk | ft -autosize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ドライブ構成2(ドライブレター/ファイルシステム) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-Volume | ft -autosize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** タイムゾーン ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Class Win32_TimeZone -Namespace "Root\CIMV2" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** 参加ドメイン/ワークグループ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$CompInfo = Get-WmiObject -NameSpace root\CIMV2 -Class Win32_ComputerSystem

switch($CompInfo.PartOfDomain){
  $true {
    $DomainType = "ドメイン"
    $DomainName = $CompInfo.Domain
  }
  $false {
    $DomainType = "ワークグループ"
    $DomainName = $CompInfo.Workgroup
  }
  default {
    $DomainType = "不明"
    $DomainName = "不明"
  }
}

echo $DomainType" : "$DomainName | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** 管理者権限 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** Enable             :アカウントを無効にする(無効の場合(チェックありの場合)は、False)" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** LockOut            :アカウントのロックアウト" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** CantPasswordChange :ユーザーはパスワードを変更できない" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** DontExpirePassword :パスワードを無期限にする" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** LogonPasswordChange:ユーザーは次回ログイン時にパスワードの変更が必要" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

$ADSI = [ADSI]("WinNT://{0}" -f $Env:ComputerName)
$Users = $ADSI.Children | Where-Object { $_.SchemaClassName -eq "user" }
$Users | Foreach-Object {
    $Name = $_.Name[0]
    $Flags = $_.Get("UserFlags")[0]

    $user = New-Object psobject
    $user | Add-Member noteproperty ComputerName        $Env:ComputerName
    $user | Add-Member noteproperty Name                $Name
    $user | Add-Member noteproperty Enable              (($Flags -band 0x2     ) -eq 0)
    $user | Add-Member noteproperty LockOut             (($Flags -band 0x10    ) -ne 0)
    $user | Add-Member noteproperty CantPasswordChange  (($Flags -band 0x40    ) -ne 0)
    $user | Add-Member noteproperty DontExpirePassword  (($Flags -band 0x10000 ) -ne 0)
    $user | Add-Member noteproperty LogonPasswordChange (($Flags -band 0x800000) -ne 0)

    return $user
} | Where-Object { $_.Name -eq "Administrator" } | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## ネットワーク構成 ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** インターフェース設定確認 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** 【確認対象項目(インターフェース固有)】" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  接続名" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-NetAdapter | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** 【確認対象項目(インターフェース固有)】" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  各インターフェースのプロパティ" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-NetAdapterBinding | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** 【確認対象項目(インターフェース固有)】" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  IPアドレスを自動的に取得する" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  次のIPアドレスを使う" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  次の DNSサーバーのアドレスを自動的に取得する" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  次の DNSサーバーのアドレスを使う" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-IP設定-IPアドレス" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-IP設定-デフォルトゲートウェイ-ゲートウェイ" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-DNS-DNSサーバーアドレス（使用順）" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

cmd /c 'ipconfig /all' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** 【確認対象項目(デフォルトゲートウェイが設定されたインターフェースのみ)】" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-IP設定-デフォルトゲートウェイ-メトリック" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  IPv4ルートテーブル固定ルートのメトリックを確認する 規定と記載があった場合は、「自動」となる" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

cmd /c 'netstat -r' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** 【確認対象項目(全インターフェース共通)】" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-DNS SearchListに文字列なし:プライマリおよび接続専用のDNSサフィックスを追加する 文字列あり:以下のDNSサフィックスを順に追加する" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters' -Name "SearchList" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** 【確認対象項目(全インターフェース共通)】" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-DNS-プライマリ DNSサフィックスの親サフィックスを追加する 1:有効 0:無効" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters' -Name "UseDomainNameDevolution" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** 【確認対象項目(インターフェース固有)】" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-DNS-この接続のアドレスをDNSに登録する        : RegisterThisConnectionsAddress" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  詳細設定-DNS-この接続のDNSサフィックスをDNS登録に使う : UseSuffixWhenRegistering" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-DnsClient | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** IPv6無効(16進数：0xff 10進数:255) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name "DisabledComponents" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## サーバ設定 ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** リモート管理 1:有効 0またはキーが存在しない:無効 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$RA_CHECK = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
echo "キーの存在確認 : $RA_CHECK" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name "fAllowToGetHelp" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** リモートデスクトップ 1:許可しない 0:許可する ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" | fl *fDenyTSConnections | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** リモートデスクトップ ネットワークレベル認証  1:許可する 0:許可しない ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" | fl *UserAuthentication | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** 仮想メモリ（すべてのドライブのページングファイルのサイズを自動的に管理する） ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'wmic computersystem get AutomaticManagedPagefile' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** 仮想メモリ（ドライブ/サイズ） ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Class Win32_PageFileSetting | select-Object Name,InitialSize,Maximumsize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ユーザーアカウント制御 1:通知しない ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PoliciesSystem' -Name "LocalAccountTokenFilterPolicy" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** システムエラー ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** LogEvent 1:有効 / AutoReboot 1:有効 / CrashDumpEnabled 1:完全 7:自動 / DumpFile" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** Overwrite 1:有効 / AlwaysKeepMemoryDump 0または存在しない:無効" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** Windows Update ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "ドメインのグループポリシーにて反映するため、確認対象外とする" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** Windows ファイアウォール ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-NetFirewallProfile | fl -Property Name,Enabled | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** 電源オプション ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Name root\cimv2\power -Class Win32_PowerPlan | select elementname,isactive | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** IE SECの構成(Administrators) 1:オン 0:オフ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name "IsInstalled" | fl *IsInstalled | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** IE SECの構成(Users)  1:オン 0:オフ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name "IsInstalled" | fl *IsInstalled | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** SNPの無効化 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'netsh int tcp show global' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** SMB SmbClientConfiguration ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-SmbClientConfiguration | fl *MultiChannel | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** SMB SmbServerConfiguration ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-SmbServerConfiguration | fl *MultiChannel | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** イベントビューアー(Setup以外) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-EventLog -List | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** イベントビューアー(Setup 単位:byte) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
wevtutil gl Setup | findstr /C:name: /C:maxSize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ローカルセキュリティポリシー - パスワードのポリシー/アカウントロックアウトのポリシー ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** ResetLockoutCount/LockoutDurationは、LockoutBadCountが0以外の場合のみ表示。その他は、規定値(該当なし)。 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'secedit /export /areas SECURITYPOLICY /cfg '$Path\${hostname}_${DATE}_Paramater_Check_Sec.txt
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"MinimumPasswordLength "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"MinimumPasswordAge "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"MaximumPasswordAge "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"PasswordHistorySize "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"ClearTextPassword "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"PasswordComplexity "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"LockoutBadCount "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"ResetLockoutCount "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'type ' $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt | findstr /C:"LockoutDuration "  | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Remove-Item $Path\${hostname}_${DATE}_Paramater_Check_Sec.txt

echo "`r`n" "****** ローカルセキュリティポリシー - Endpoint Protection 1:有効 ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name "DisableAntiSpyware" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## サーバー役割/機能 ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WindowsFeature | ft -AutoSize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## プログラム ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject Win32_InstalledWin32Program | Select-Object Name,Version  | Sort-Object Name | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## サービス ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$triggers = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object { $_.GetSubkeyNames().Contains("TriggerInfo") } | ForEach-Object { $_.Name.Split("\")[-1] }
$startMode = @{ Manual = "手動"; Disabled = "無効"; Auto = "自動"; Unknown = "不明" }
$startOption = @{ 01 = " (トリガー開始)"; 10 = " (遅延開始)"; 11 = " (遅延開始、トリガー開始)" }

$serviceData = Get-CimInstance -ClassName Win32_Service | Select-Object @(
    @{ n = "状態";                e = { if($_.State -eq "Running") { "実行" } else { "停止" } } }
    @{ n = "スタートアップの種類"; e = { $startMode[$_.StartMode] + $startOption[10 * ($_.StartMode -eq "Auto" -and $_.DelayedAutoStart) + $triggers.Contains($_.Name)] } }
    @{ n = "表示名";              e = { $_.DisplayName } }
    @{ n = "サービス名";          e = { $_.Name } }
    @{ n = "ログオン";            e = { $_.startname } }
)

$serviceData | select 表示名,状態,スタートアップの種類 | sort -Property 表示名 | ConvertTo-Csv -NoTypeInformation -Delimiter `t | % {$_ -replace '"',''} | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## Windows Update ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WMIObject Win32_QuickFixEngineering | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

