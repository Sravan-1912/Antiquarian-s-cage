<#
  Creates the isolated Windows 11 test VM for the phone sign-in tile (VirtualBox 7.2, files on D:).

  Usage:  .\create-test-vm.ps1 -Iso D:\ISO\Win11.iso
  After Windows is installed inside the VM, take the snapshot "clean-install" (the script prints the command) so the
  VM can always be rolled back after testing the credential provider.

  Network: VirtualBox NAT - the VM reaches the host's dev API at http://10.0.2.2:8000; nothing on your LAN can reach
  the VM.
#>
param(
    [Parameter(Mandatory = $true)][string]$Iso,
    [string]$Name = 'CageTestWin11',
    [string]$BaseFolder = 'D:\VMs',
    [int]$MemoryMB = 4096,
    [int]$Cpus = 2,
    [int]$DiskGB = 64
)
$ErrorActionPreference = 'Continue'   # VBoxManage writes progress to stderr; exit codes are checked explicitly
$vbm = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
function Run([string[]]$a) { & $vbm @a; if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($a -join ' ') failed ($LASTEXITCODE)" } }

if (-not (Test-Path $Iso)) { throw "ISO not found: $Iso" }
if ((& $vbm list vms) -match "`"$Name`"") { throw "A VM named $Name already exists - not touching it" }
New-Item -ItemType Directory -Force $BaseFolder | Out-Null

Run @('createvm', '--name', $Name, '--ostype', 'Windows11_64', '--register', '--basefolder', $BaseFolder)
Run @('modifyvm', $Name, '--memory', "$MemoryMB", '--cpus', "$Cpus", '--firmware', 'efi', '--tpm-type', '2.0',
      '--graphicscontroller', 'vboxsvga', '--vram', '128', '--nic1', 'nat', '--clipboard-mode', 'disabled',
      '--drag-and-drop', 'disabled', '--audio-driver', 'none')
Run @('modifynvram', $Name, 'inituefivarstore')
Run @('modifynvram', $Name, 'enrollmssignatures')
Run @('modifynvram', $Name, 'enrollorclplatformkey')
$disk = Join-Path $BaseFolder "$Name\$Name.vdi"
Run @('createmedium', 'disk', '--filename', $disk, '--size', "$($DiskGB * 1024)", '--format', 'VDI')
Run @('storagectl', $Name, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci', '--portcount', '2')
Run @('storageattach', $Name, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', $disk)
Run @('storageattach', $Name, '--storagectl', 'SATA', '--port', '1', '--device', '0', '--type', 'dvddrive', '--medium', $Iso)

Write-Output "Created $Name (EFI, TPM 2.0, Secure Boot, ${MemoryMB} MB, $Cpus CPUs, ${DiskGB} GB on $BaseFolder)."
Write-Output "Start it:   & '$vbm' startvm $Name"
Write-Output "After Windows setup finishes:  & '$vbm' snapshot $Name take clean-install"
