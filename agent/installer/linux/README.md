# Cage endpoint agent — Linux

The same `cage-agent` application runs on Linux (systemd distributions: Debian/Ubuntu, Fedora/RHEL, and similar). It
enrols with a one-time token, reports inventory and security/compliance state, sends heartbeats, and executes signed
remote actions and policy deployments — the Linux counterparts of the Windows features.

## Quick start

From source (any machine with Python 3.11+):
```bash
cd agent
python3 -m cage_agent collect     # dry run: prints what this host would report, no network
```

Build a single-file binary and install as a service (do this on the target distro family):
```bash
cd agent
./installer/linux/build-linux.sh                       # -> dist/cage-agent
sudo ./installer/linux/install.sh \
     --server https://your-cage-server \
     --token  XXXXX-XXXXX-XXXXX-XXXXX-XXXXX             # one-time token from the console
```
The device appears in the console under **Endpoints** within a heartbeat interval.

- Logs: `journalctl -u cage-agent -f`
- Remove: revoke in the console, then `sudo ./installer/linux/uninstall.sh [--purge]`

## What maps to what

| Area | Linux implementation |
|---|---|
| Device key at rest | AES-256-GCM wrapped with a key derived from `/etc/machine-id`, file mode `0600` (no DPAPI) |
| Data dir | `/var/lib/cage-agent` (service/root) or `~/.config/cage-agent` (user scope) |
| Inventory | psutil + `/etc/os-release`, `uname`, DMI (`/sys/class/dmi/id/*`), `/proc/cpuinfo` |
| Firewall | ufw / firewalld / nftables / iptables |
| Disk encryption (BitLocker) | LUKS/dm-crypt on root (`lsblk`, `findmnt`) |
| Secure Boot | `mokutil --sb-state` |
| Antivirus (Defender) | ClamAV daemon + on-access (`clamonacc`) |
| Remote access (RDP) | OpenSSH (`sshd` state, PasswordAuthentication/PermitRootLogin) |
| Screen lock | GNOME via dconf system db / gsettings |
| Updates | apt/dnf history + `unattended-upgrades` / `dnf-automatic` |
| Account/password policy | `/etc/login.defs`, `pam_faillock` |
| Audit | `auditd` + `auditctl -l` |
| USB storage | modprobe blacklist / `usbguard` |
| Remote actions | lock (`loginctl lock-sessions`), restart (`shutdown -r`), account lock/unlock (`usermod`), de-sudo (`gpasswd`) |

## Notes & limits
- The service runs **as root** (the Linux equivalent of the Windows SYSTEM broker); there is no separate broker process.
- Checks that need privileges the agent lacks are reported **unknown**, never compliant (same tri-state as Windows).
- Policy enforcement targets the common systemd distros; where a change can't be made safely at runtime (e.g. encrypting
  an already-mounted root filesystem), the agent reports **needs_attention** with guidance instead of acting.
- **Not yet verified end-to-end on a live Linux endpoint** — the Windows path is unchanged and still fully tested.
