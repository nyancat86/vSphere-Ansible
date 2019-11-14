###############################################
# Windows Server OS �p�����[�^�`�F�b�N�c�[��  #
###############################################
$Path = ".\"
$hostname = hostname
$DATE = Get-Date -Format "yyyyMMdd"
$DATE_OUTPUT = Get-Date -Format "yyyy/MM/dd HH:mm:ss"

echo "########## �m�F�Ώ� ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt
echo "�z�X�g�� : $hostname" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "�擾���� : $DATE_OUTPUT" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## �m�F�Ώۊ�{��� ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'systeminfo' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## ��{�ݒ� ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** OS��/Edition/Service Pack ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
(Get-WmiObject Win32_OperatingSystem).Caption | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ���C�Z���X�F�� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cscript "C:\Windows\System32\slmgr.vbs" /dli | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �R���s���[�^�� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
(Get-CimInstance -Class Win32_ComputerSystem).Name | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** CPU ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$PhysicalSockets=(Get-WmiObject Win32_ComputerSystem).NumberOfProcessors
echo "�\�P�b�g�� : $PhysicalSockets" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

$PhysicalCores = 0
(Get-WmiObject Win32_Processor).NumberOfCores | %{ $PhysicalCores += $_}
echo "�R�A��     : $PhysicalCores" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ������ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Class Win32_PhysicalMemory |%{ $_.Capacity}| Measure-Object -Sum | %{ ($_.sum /1024/1024/1024).toString()+"GB"}| Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �h���C�u�\��1(�e��/�p�[�e�B�V�����̃X�^�C��) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-Disk | ft -autosize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �h���C�u�\��2(�h���C�u���^�[/�t�@�C���V�X�e��) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-Volume | ft -autosize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �^�C���]�[�� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Class Win32_TimeZone -Namespace "Root\CIMV2" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �Q���h���C��/���[�N�O���[�v ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$CompInfo = Get-WmiObject -NameSpace root\CIMV2 -Class Win32_ComputerSystem

switch($CompInfo.PartOfDomain){
  $true {
    $DomainType = "�h���C��"
    $DomainName = $CompInfo.Domain
  }
  $false {
    $DomainType = "���[�N�O���[�v"
    $DomainName = $CompInfo.Workgroup
  }
  default {
    $DomainType = "�s��"
    $DomainName = "�s��"
  }
}

echo $DomainType" : "$DomainName | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �Ǘ��Ҍ��� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** Enable             :�A�J�E���g�𖳌��ɂ���(�����̏ꍇ(�`�F�b�N����̏ꍇ)�́AFalse)" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** LockOut            :�A�J�E���g�̃��b�N�A�E�g" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** CantPasswordChange :���[�U�[�̓p�X���[�h��ύX�ł��Ȃ�" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** DontExpirePassword :�p�X���[�h�𖳊����ɂ���" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** LogonPasswordChange:���[�U�[�͎��񃍃O�C�����Ƀp�X���[�h�̕ύX���K�v" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

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

echo "`r`n" "########## �l�b�g���[�N�\�� ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** �C���^�[�t�F�[�X�ݒ�m�F ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** �y�m�F�Ώۍ���(�C���^�[�t�F�[�X�ŗL)�z" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڑ���" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-NetAdapter | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** �y�m�F�Ώۍ���(�C���^�[�t�F�[�X�ŗL)�z" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �e�C���^�[�t�F�[�X�̃v���p�e�B" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-NetAdapterBinding | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** �y�m�F�Ώۍ���(�C���^�[�t�F�[�X�ŗL)�z" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  IP�A�h���X�������I�Ɏ擾����" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  ����IP�A�h���X���g��" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  ���� DNS�T�[�o�[�̃A�h���X�������I�Ɏ擾����" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  ���� DNS�T�[�o�[�̃A�h���X���g��" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-IP�ݒ�-IP�A�h���X" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-IP�ݒ�-�f�t�H���g�Q�[�g�E�F�C-�Q�[�g�E�F�C" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-DNS-DNS�T�[�o�[�A�h���X�i�g�p���j" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

cmd /c 'ipconfig /all' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** �y�m�F�Ώۍ���(�f�t�H���g�Q�[�g�E�F�C���ݒ肳�ꂽ�C���^�[�t�F�[�X�̂�)�z" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-IP�ݒ�-�f�t�H���g�Q�[�g�E�F�C-���g���b�N" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  IPv4���[�g�e�[�u���Œ胋�[�g�̃��g���b�N���m�F���� �K��ƋL�ڂ��������ꍇ�́A�u�����v�ƂȂ�" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

cmd /c 'netstat -r' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** �y�m�F�Ώۍ���(�S�C���^�[�t�F�[�X����)�z" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-DNS SearchList�ɕ�����Ȃ�:�v���C�}������ѐڑ���p��DNS�T�t�B�b�N�X��ǉ����� �����񂠂�:�ȉ���DNS�T�t�B�b�N�X�����ɒǉ�����" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters' -Name "SearchList" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** �y�m�F�Ώۍ���(�S�C���^�[�t�F�[�X����)�z" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-DNS-�v���C�}�� DNS�T�t�B�b�N�X�̐e�T�t�B�b�N�X��ǉ����� 1:�L�� 0:����" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters' -Name "UseDomainNameDevolution" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "*** �y�m�F�Ώۍ���(�C���^�[�t�F�[�X�ŗL)�z" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-DNS-���̐ڑ��̃A�h���X��DNS�ɓo�^����        : RegisterThisConnectionsAddress" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "***  �ڍאݒ�-DNS-���̐ڑ���DNS�T�t�B�b�N�X��DNS�o�^�Ɏg�� : UseSuffixWhenRegistering" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-DnsClient | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** IPv6����(16�i���F0xff 10�i��:255) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name "DisabledComponents" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## �T�[�o�ݒ� ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** �����[�g�Ǘ� 1:�L�� 0�܂��̓L�[�����݂��Ȃ�:���� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$RA_CHECK = test-path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
echo "�L�[�̑��݊m�F : $RA_CHECK" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name "fAllowToGetHelp" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �����[�g�f�X�N�g�b�v 1:�����Ȃ� 0:������ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" | fl *fDenyTSConnections | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �����[�g�f�X�N�g�b�v �l�b�g���[�N���x���F��  1:������ 0:�����Ȃ� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" | fl *UserAuthentication | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ���z�������i���ׂẴh���C�u�̃y�[�W���O�t�@�C���̃T�C�Y�������I�ɊǗ�����j ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'wmic computersystem get AutomaticManagedPagefile' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ���z�������i�h���C�u/�T�C�Y�j ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Class Win32_PageFileSetting | select-Object Name,InitialSize,Maximumsize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ���[�U�[�A�J�E���g���� 1:�ʒm���Ȃ� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PoliciesSystem' -Name "LocalAccountTokenFilterPolicy" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �V�X�e���G���[ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** LogEvent 1:�L�� / AutoReboot 1:�L�� / CrashDumpEnabled 1:���S 7:���� / DumpFile" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "*** Overwrite 1:�L�� / AlwaysKeepMemoryDump 0�܂��͑��݂��Ȃ�:����" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** Windows Update ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "�h���C���̃O���[�v�|���V�[�ɂĔ��f���邽�߁A�m�F�ΏۊO�Ƃ���" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** Windows �t�@�C�A�E�H�[�� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-NetFirewallProfile | fl -Property Name,Enabled | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �d���I�v�V���� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject -Name root\cimv2\power -Class Win32_PowerPlan | select elementname,isactive | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** IE SEC�̍\��(Administrators) 1:�I�� 0:�I�t ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name "IsInstalled" | fl *IsInstalled | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** IE SEC�̍\��(Users)  1:�I�� 0:�I�t ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name "IsInstalled" | fl *IsInstalled | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** SNP�̖����� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
cmd /c 'netsh int tcp show global' | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** SMB SmbClientConfiguration ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-SmbClientConfiguration | fl *MultiChannel | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** SMB SmbServerConfiguration ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-SmbServerConfiguration | fl *MultiChannel | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �C�x���g�r���[�A�[(Setup�ȊO) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-EventLog -List | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** �C�x���g�r���[�A�[(Setup �P��:byte) ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
wevtutil gl Setup | findstr /C:name: /C:maxSize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "****** ���[�J���Z�L�����e�B�|���V�[ - �p�X���[�h�̃|���V�[/�A�J�E���g���b�N�A�E�g�̃|���V�[ ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
echo "****** ResetLockoutCount/LockoutDuration�́ALockoutBadCount��0�ȊO�̏ꍇ�̂ݕ\���B���̑��́A�K��l(�Y���Ȃ�)�B ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
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

echo "`r`n" "****** ���[�J���Z�L�����e�B�|���V�[ - Endpoint Protection 1:�L�� ******" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name "DisableAntiSpyware" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## �T�[�o�[����/�@�\ ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WindowsFeature | ft -AutoSize | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## �v���O���� ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WmiObject Win32_InstalledWin32Program | Select-Object Name,Version  | Sort-Object Name | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## �T�[�r�X ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
$triggers = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object { $_.GetSubkeyNames().Contains("TriggerInfo") } | ForEach-Object { $_.Name.Split("\")[-1] }
$startMode = @{ Manual = "�蓮"; Disabled = "����"; Auto = "����"; Unknown = "�s��" }
$startOption = @{ 01 = " (�g���K�[�J�n)"; 10 = " (�x���J�n)"; 11 = " (�x���J�n�A�g���K�[�J�n)" }

$serviceData = Get-CimInstance -ClassName Win32_Service | Select-Object @(
    @{ n = "���";                e = { if($_.State -eq "Running") { "���s" } else { "��~" } } }
    @{ n = "�X�^�[�g�A�b�v�̎��"; e = { $startMode[$_.StartMode] + $startOption[10 * ($_.StartMode -eq "Auto" -and $_.DelayedAutoStart) + $triggers.Contains($_.Name)] } }
    @{ n = "�\����";              e = { $_.DisplayName } }
    @{ n = "�T�[�r�X��";          e = { $_.Name } }
    @{ n = "���O�I��";            e = { $_.startname } }
)

$serviceData | select �\����,���,�X�^�[�g�A�b�v�̎�� | sort -Property �\���� | ConvertTo-Csv -NoTypeInformation -Delimiter `t | % {$_ -replace '"',''} | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

echo "`r`n" "########## Windows Update ##########" | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append
Get-WMIObject Win32_QuickFixEngineering | Out-File $Path\${hostname}_${DATE}_Paramater_Check.txt -append

