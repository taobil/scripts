#!/bin/bash
## License: BSD 3
## It can reinstall debian to archlinux !.
## Written By https://github.com/taobil

function sim::log() { local _date=$(date +"%Y-%m-%d %H:%M:%S"); echo -e "\e[0;32m[${_date}]\e[0m $@" >&2; }
function sim::fatal() { sim::log "$@"; sim::log "Exiting."; exit 1; }
function sim::command_exists() { command -v "$1" > /dev/null 2>&1; }
function sim::module_exists() { lsmod | grep -q "^$1\b" && return 0 || return 1; }
function sim::load_kernel_module() { modprobe "$1" 2>/dev/null; sim::module_exists "$1" || sim::fatal "[!] Module '$1' failed to load."; }
function sim::_install_command(){
  local command="$1"
  sim::log "[*] Installing $command..."
  apt update -qq -y
  apt install -qq -y "${command}" && sim::log "[*] '$command' has been installed successfully." || sim::fatal "[!] Failed to install '$command'."
}
function sim::install_command(){
  local command="$1"
  case "$1" in
    xz)
      sim::log "[*] Installing $command..."
       sim::_install_command 'xz-utils' 
      ;;
    wget)
      sim::_install_command 'wget'
      ;;
    mkfs.btrfs)
      sim::_install_command 'btrfs-progs'
      ;;
    mkfs.vfat)
      sim::_install_command 'dosfstools'
      ;;
    *)
      sim::fatal "[!] Unknown command: $command"
    ;;
    esac
}

function sim::ensure_command_exist(){
  sim::log "[*] Installing missing command..."
  local need_commands=(xz wget mkfs.btrfs mkfs.vfat)
    for cmd in "${need_commands[@]}"; do
       if ! sim::command_exists "$cmd"; then sim::install_command "$cmd"; fi
  done
}

function sim::ensure_load_kernerl_modules(){
  sim::log "[*] Loading kernel modules..."
  local need_modules=(btrfs vfat nls_cp437 nls_ascii nls_utf8)
  for module in "${need_modules[@]}"; do
        sim::load_kernel_module "$module"
  done
}


[ ${EUID} -eq 0 ] || sim::fatal '[!] This script must be run as root.'
[ ${UID} -eq 0 ] || sim::fatal '[!] This script must be run as root.'
[ "$(grep -q "ID=debian" /etc/os-release; echo $?)" -eq 0 ] || sim::fatal '[-] This script only supports Debian systems.'
sim::ensure_command_exist
sim::ensure_load_kernerl_modules

sim_root='/sim'
password='sim@@@'
ver='linux'
mirror='https://mirrors.kernel.org/archlinux'
base_packages='btrfs-progs dosfstools openssh grub sudo reflector'
extra_packages='curl wget bash-completion screen'
dhcp=false
uefi=$([ -d /sys/firmware/efi ] && echo true || echo false)
disk="/dev/$(lsblk -no PKNAME "$(df /boot | grep -Eo '/dev/[a-z0-9]+')")"
interface=$(ls /sys/class/net | grep -v lo)
ip_mac=$(ip link show "${interface}" | awk '/link\/ether/{print $2}')
ip4_addr=$(ip -o -4 addr show dev "${interface}" | awk '{print $4}' | head -n 1)
ip4_gw=$(ip route show dev "${interface}" | awk '/default/{print $3}' | head -n 1)
ip6_addr=$(ip -o -6 addr show dev "${interface}" | awk '{print $4}' | head -n 1)
ip6_gw=$(ip -6 route show dev "${interface}" | awk '/default/{print $3}' | head -n 1)

machine=$(uname -m)
case ${machine} in
  aarch64|arm64) machine_warp="arm64";;
  x86_64|amd64) machine_warp="amd64";;
  *) machine_warp="";;
esac

function sim::cleanup_exit(){
  sim::log "[*] Clearing temporary files..."
  swapoff -a
  losetup -D || true
  #fuser -kvm "${sim_root}" -15
  if mountpoint -q ${sim_root}; then
    umount -d ${sim_root}
  fi
  rm -rf --one-file-system ${sim_root}
}
function sim::cleanup_warp_exit(){ set +e;sim::cleanup_exit; }

function sim::copy_important_config(){ 
  sim::log "[*] Copying important config into new system and more configuration..."
  mkdir -p "${sim_root}/etc"
  #cp -axL --remove-destination /etc/resolv.conf "${sim_root}/etc"
  sim::log "[*] Copying or user custom resolv.conf..."
  local nameserver="nameserver 8.8.8.8\nnameserver 1.1.1.1\nnameserver 2606:4700:4700::1111"
  echo -e "${nameserver}" > "${sim_root}/etc/resolv.conf"
  return 0
}

function sim::_download_ramos_and_extract(){
  local mirror='https://images.linuxcontainers.org'
  sim::log "[*] Get latest download link..."
  local response=$(wget -qO- "${mirror}/images/alpine/edge/${machine_warp}/default/?C=M;O=D")
  local build_time=$(echo "$response" | grep -oP '(\d{8}_\d{2}:\d{2})' | tail -n 1)
  local link="${mirror}/images/alpine/edge/${machine_warp}/default/${build_time}/rootfs.tar.xz"

  sim::log "[*] Downloading temporary and extract..."
  local tmp_file=$(mktemp /tmp/rootfs.tar.xz.XXXXXX)
  if wget --continue -q --show-progress -O "${tmp_file}" "${link}"; then
    if [ -s "${tmp_file}" ]; then
      tar -xJf "${tmp_file}" --directory="${sim_root}" --strip-components=1
      sim::log "[*] Download and extract completed successfully."
    else
      sim::fatal "[!] Downloaded file is empty."
    fi
  else
      sim::fatal "[!] Failed to download from '${link}'."
  fi
  rm -f "${tmp_file}"
}

function sim::install_ramos_packages(){
  sim::log "[*] Installing dropbear and depends into ramos..."
  chroot ${sim_root} apk update
  # e2fsprogs = mkfs.ext2, mkfs.ext3, mkfs.ext4
  chroot ${sim_root} apk -q add eudev bash dropbear sgdisk zstd dosfstools btrfs-progs debootstrap arch-install-scripts
  chroot ${sim_root} mkdir -p /etc/dropbear
  chroot ${sim_root} dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key
  chroot ${sim_root} dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
  chroot ${sim_root} bash -c 'echo "DROPBEAR_PORT=22" >> /etc/conf.d/dropbear'
  chroot ${sim_root} bash -c 'echo "DROPBEAR_EXTRA_ARGS=\"-w -K 5\"" >> /etc/conf.d/dropbear'
  chroot ${sim_root} bash -c "echo 'root:${password}' | chpasswd"
}

function sim::inject_init(){
  sim::log "[*] Injecting init to temporary ramos..."
  cat >${sim_root}/init<<EOF
#!/bin/bash
export PATH="\$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

uefi="${uefi}"
interface="${interface}"
ip4_addr="${ip4_addr}"
ip4_gw="${ip4_gw}"
ip6_addr="${ip6_addr}"
ip6_gw="${ip6_gw}"
password="${password}"
dhcp="${dhcp}"
disk="${disk}"
machine="${machine}"
ver="${ver}"
mirror="${mirror}"
base_packages="${base_packages}"
extra_packages="${extra_packages}"

function ramos_exit() { echo '[!] Reinstall Error! Force reboot by reboot -f . '; /bin/bash; }
exec </dev/tty0 && exec >/dev/tty0 && exec 2>/dev/tty0
trap ramos_exit EXIT

echo "[*] Ensure other processes exit ..."
sysctl -w kernel.sysrq=1 >/dev/null
echo i > /proc/sysrq-trigger

echo "[*] Reset network..."
/sbin/ip addr flush dev "${interface}"
/sbin/ip route flush dev "${interface}"
/sbin/ip addr add "${ip4_addr}" dev "${interface}"
/sbin/ip route add default via "${ip4_gw}" dev "${interface}" onlink
/sbin/ip -6 addr flush dev "${interface}"
/sbin/ip -6 route flush dev "${interface}"
/sbin/ip -6 addr add "${ip6_addr}" dev "${interface}"
/sbin/ip -6 route add default via "${ip6_gw}" dev "${interface}" onlink
/usr/sbin/dropbear

udevadm info -n ${disk} -q property

# Partition & Formatting & Mounting
if [ "\${uefi}" = "true" ]; then
  sgdisk -g --align-end --clear \
    --new 0:0:+100M --typecode=0:ef00 --new 0:0:0 --typecode=0:8300 \${disk}
else
  sgdisk -g --align-end --clear \
    --new 0:0:+1M --typecode=0:ef02 --new 0:0:0 --typecode=0:8300 \${disk}
fi

partprobe
[[ \$disk == /dev/nvme* ]] && disk="\${disk}p"

mkfs.btrfs -f -L LINUX \${disk}2
mount -o compress-force=zstd \${disk}2 /mnt
btrfs subvolume create /mnt/@
btrfs subvolume create /mnt/@tmp
btrfs subvolume create /mnt/@swap
btrfs subvolume create /mnt/@var_tmp
btrfs subvolume create /mnt/@var_cache
chattr +C /mnt/@tmp
chattr +C /mnt/@swap
chattr +C /mnt/@var_tmp
chattr +C /mnt/@var_cache
umount /mnt
mount -o compress-force=zstd,subvol=@ \${disk}2 /mnt
mkdir -p /mnt/{swap,tmp} /mnt/var/{tmp,cache}
mount -o subvol=@tmp \${disk}2 /mnt/tmp
mount -o subvol=@swap \${disk}2 /mnt/swap
mount -o subvol=@var_tmp \${disk}2 /mnt/var/tmp
mount -o subvol=@var_cache \${disk}2 /mnt/var/cache
btrfs filesystem mkswapfile /mnt/swap/swapfile --uuid clear --size 1G
swapon /mnt/swap/swapfile

# Mounting EFI
if [ "\${uefi}" = "true" ]; then
  mkfs.vfat -F32 -n EFI \${disk}1
  mkdir -p /mnt/boot/efi
  mount \${disk}1 /mnt/boot/efi
fi

# Downloading bootstrap...
wget -q -O - "\${mirror}/iso/latest/archlinux-bootstrap-\${machine}.tar.zst" | zstd -d | tar -xf - --directory=/mnt --strip-components=1

 
# Mounting for chroot
mount -t proc /proc /mnt/proc
mount --rbind /dev /mnt/dev
mount --rbind /sys /mnt/sys

# Genfstab
genfstab -U /mnt >> /mnt/etc/fstab
cp /etc/resolv.conf /mnt/etc/resolv.conf

# Setup systemd-networkd
if [ "\$dhcp" = "true" ]; then
  cat > /mnt/etc/systemd/network/default.network <<EOFIN
[Match]
Name=en* eth*
[Network]
DHCP=yes
[DHCP]
UseMTU=yes
UseDNS=yes
UseDomains=yes
EOFIN
else
  cat > /mnt/etc/systemd/network/default.network <<EOFIN
[Match]
Name=en* eth*

[Network]
Address=${ip4_addr}
DNS=8.8.8.8
[Route]
Gateway=${ip4_gw}
GatewayOnlink=true

[Network]
IPv6AcceptRA=0
Address=${ip6_addr}
DNS=2606:4700:4700::1111
[Route]
Gateway=${ip6_gw}
GatewayOnlink=true
EOFIN
fi

# Setup pacman
sed -i 's|#Color|Color|' /mnt/etc/pacman.conf
sed -i 's|#ParallelDownloads|ParallelDownloads|' /mnt/etc/pacman.conf
echo 'Server = https://mirrors.edge.kernel.org/archlinux/\$repo/os/\$arch' >> /mnt/etc/pacman.d/mirrorlist

# Install base system
chroot /mnt pacman-key --init
chroot /mnt pacman-key --populate archlinux
chroot /mnt pacman --disable-sandbox -Syy
chroot /mnt pacman --disable-sandbox --needed --noconfirm -S archlinux-keyring
chroot /mnt pacman --disable-sandbox --needed --noconfirm -S $base_packages $extra_packages ${ver} linux-firmware
chroot /mnt reflector -l 18 -p https --sort rate --save /etc/pacman.d/mirrorlist
# Install 
if [ "\$uefi" = "true" ]; then
  chroot /mnt pacman --disable-sandbox --needed --noconfirm -S efibootmgr
fi

# Setup locale & hostname
sed -ri 's/^#\s*en_US/en_US/' /mnt/etc/locale.gen
echo -e "LANGUAGE=en_US:en\nLC_ALL=en_US.UTF-8\nLANG=en_US.UTF-8" > /mnt/etc/default/locale
chroot /mnt locale-gen
chroot /mnt ln -sf /usr/share/zoneinfo/UTC /etc/localtime
echo 'localhost'> /mnt/etc/hostname

# Setting Account
chroot /mnt systemctl set-default multi-user.target
echo "root:${password}" |  chroot /mnt chpasswd
chroot /mnt ssh-keygen -t ed25519 -f /etc/ssh/ed25519_key -N ""
chroot /mnt ssh-keygen -t rsa -b 4096 -f /etc/ssh/rsa_key -N ""

# Enable systemd-timesyncd
cat > /mnt/etc/systemd/timesyncd.conf <<EOFIN
[Time]
NTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org
EOFIN

# Enable systemd services
chroot /mnt systemctl enable systemd-timesyncd.service
chroot /mnt systemctl enable systemd-networkd.service
chroot /mnt systemctl enable sshd.service

# Enable root login and Optimizing system parameters
chroot /mnt /bin/bash -c "echo 'IyEvYmluL2Jhc2gKCmNhdCA+IC9ldGMvc3NoL3NzaGRfY29uZmlnIDw8RU9GCiNJbmNsdWRlIC9ldGMvc3NoL3NzaGRfY29uZmlnLmQvKi5jb25mClBvcnQgIDIyClBlcm1pdFJvb3RMb2dpbiB5ZXMKUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMKUHVia2V5QXV0aGVudGljYXRpb24geWVzCkNoYWxsZW5nZVJlc3BvbnNlQXV0aGVudGljYXRpb24gbm8KS2JkSW50ZXJhY3RpdmVBdXRoZW50aWNhdGlvbiBubwpBdXRob3JpemVkS2V5c0ZpbGUgIC9yb290Ly5zc2gvYXV0aG9yaXplZF9rZXlzClgxMUZvcndhcmRpbmcgeWVzCkFsbG93VXNlcnMgcm9vdApQcmludE1vdGQgbm8KQWNjZXB0RW52IExBTkcgTENfKgpFT0YKCl9mdHA9JChmaW5kIC91c3IgLW5hbWUgInNmdHAtc2VydmVyIiAyPi9kZXYvbnVsbCB8IGhlYWQgLW4gMSkKWyAtbiAiJHtfZnRwfSIgXSAmJiBlY2hvICJTdWJzeXN0ZW0gc2Z0cCAke19mdHB9IiA+PiAvZXRjL3NzaC9zc2hkX2NvbmZpZwoKY2F0ID4+IC9ldGMvYmFzaC5iYXNocmMgPDxFT0YKZXhwb3J0IFBTMT0nXFtcZVswOzMybVxdXHVAXGggXFtcZVswOzM0bVxdXHdcW1xlWzA7MzZtXF1cblwkIFxbXGVbMG1cXScKYWxpYXMgZ2V0aXA9J2N1cmwgLS1jb25uZWN0LXRpbWVvdXQgMyAtTHMgaHR0cHM6Ly9pcHY0LWFwaS5zcGVlZHRlc3QubmV0L2dldGlwJwphbGlhcyBnZXRpcDY9J2N1cmwgLS1jb25uZWN0LXRpbWVvdXQgMyAtTHMgaHR0cHM6Ly9pcHY2LWFwaS5zcGVlZHRlc3QubmV0L2dldGlwJwphbGlhcyBuZXRjaGVjaz0ncGluZyAtYzIgMS4xLjEuMScKYWxpYXMgbHM9J2xzIC0tY29sb3I9YXV0bycKYWxpYXMgZ3JlcD0nZ3JlcCAtLWNvbG9yPWF1dG8nIAphbGlhcyBmZ3JlcD0nZmdyZXAgLS1jb2xvcj1hdXRvJwphbGlhcyBlZ3JlcD0nZWdyZXAgLS1jb2xvcj1hdXRvJwphbGlhcyBybT0ncm0gLWknCmFsaWFzIGNwPSdjcCAtaScKYWxpYXMgbXY9J212IC1pJwphbGlhcyBsbD0nbHMgLWxoJwphbGlhcyBsYT0nbHMgLWxBaCcKYWxpYXMgLi49J2NkIC4uLycKYWxpYXMgLi4uPSdjZCAuLi8uLi8nCmFsaWFzIHBnPSdwcyBhdXggfGdyZXAgLWknCmFsaWFzIGhnPSdoaXN0b3J5IHxncmVwIC1pJwphbGlhcyBsZz0nbHMgLUEgfGdyZXAgLWknCmFsaWFzIGRmPSdkZiAtVGgnCmFsaWFzIGZyZWU9J2ZyZWUgLWgnCmV4cG9ydCBISVNUVElNRUZPUk1BVD0iJUYgJVQgXGB3aG9hbWlcYCAiCmV4cG9ydCBMQU5HPWVuX1VTLlVURi04CmV4cG9ydCBQQVRIPVwkUEFUSDouCkVPRgoKWyAtZiAvZXRjL3NlY3VyaXR5L2xpbWl0cy5jb25mIF0gJiYgTElNSVQ9JzEwNDg1NzYnICYmIHNlZCAtaSAnL15cKFwqXHxyb290XClbWzpzcGFjZTpdXSpcKGhhcmRcfHNvZnRcKVtbOnNwYWNlOl1dKlwobm9maWxlXHxtZW1sb2NrXCkvZCcgL2V0Yy9zZWN1cml0eS9saW1pdHMuY29uZiAmJiBlY2hvIC1uZSAiKlx0aGFyZFx0bWVtbG9ja1x0JHtMSU1JVH1cbipcdHNvZnRcdG1lbWxvY2tcdCR7TElNSVR9XG5yb290XHRoYXJkXHRtZW1sb2NrXHQke0xJTUlUfVxucm9vdFx0c29mdFx0bWVtbG9ja1x0JHtMSU1JVH1cbipcdGhhcmRcdG5vZmlsZVx0JHtMSU1JVH1cbipcdHNvZnRcdG5vZmlsZVx0JHtMSU1JVH1cbnJvb3RcdGhhcmRcdG5vZmlsZVx0JHtMSU1JVH1cbnJvb3RcdHNvZnRcdG5vZmlsZVx0JHtMSU1JVH1cblxuIiA+Pi9ldGMvc2VjdXJpdHkvbGltaXRzLmNvbmY7CgpbIC1mIC9ldGMvc3lzdGVtZC9zeXN0ZW0uY29uZiBdICYmIHNlZCAtaSAncy8jXD9EZWZhdWx0TGltaXROT0ZJTEU9LiovRGVmYXVsdExpbWl0Tk9GSUxFPTEwNDg1NzYvJyAvZXRjL3N5c3RlbWQvc3lzdGVtLmNvbmY7CgpjYXQgPiAvZXRjL3N5c3RlbWQvam91cm5hbGQuY29uZiAgPDxFT0YKW0pvdXJuYWxdClN0b3JhZ2U9YXV0bwpDb21wcmVzcz15ZXMKRm9yd2FyZFRvU3lzbG9nPW5vClN5c3RlbU1heFVzZT04TQpSdW50aW1lTWF4VXNlPThNClJhdGVMaW1pdEludGVydmFsU2VjPTMwcwpSYXRlTGltaXRCdXJzdD0xMDAKRU9GCgpjYXQgPiAvZXRjL3N5c2N0bC5kLzk5LXN5c2N0bC5jb25mICA8PEVPRgp2bS5zd2FwcGluZXNzID0gMApuZXQuaXB2NC50Y3Bfbm90c2VudF9sb3dhdCA9IDEzMTA3MgpuZXQuY29yZS5ybWVtX21heCA9IDUzNjg3MDkxMgpuZXQuY29yZS53bWVtX21heCA9IDUzNjg3MDkxMgpuZXQuY29yZS5uZXRkZXZfbWF4X2JhY2tsb2cgPSAyNTAwMDAKbmV0LmNvcmUuc29tYXhjb25uID0gNDA5NgpuZXQuaXB2NC50Y3Bfc3luY29va2llcyA9IDEKbmV0LmlwdjQudGNwX3R3X3JldXNlID0gMQpuZXQuaXB2NC50Y3BfbWF4X3N5bl9iYWNrbG9nID0gODE5MgpuZXQuaXB2NC50Y3BfbWF4X3R3X2J1Y2tldHMgPSA1MDAwCm5ldC5pcHY0LnRjcF9mYXN0b3BlbiA9IDMKbmV0LmlwdjQudGNwX3JtZW0gPSA4MTkyIDI2MjE0NCA1MzY4NzA5MTIKbmV0LmlwdjQudGNwX3dtZW0gPSA0MDk2IDE2Mzg0IDUzNjg3MDkxMgpuZXQuaXB2NC50Y3BfYWR2X3dpbl9zY2FsZSA9IC0yCm5ldC5pcHY0LmlwX2ZvcndhcmQgPSAxCm5ldC5jb3JlLmRlZmF1bHRfcWRpc2MgPSBmcQpuZXQuaXB2NC50Y3BfY29uZ2VzdGlvbl9jb250cm9sID0gYmJyCkVPRgo=' | base64 -d | bash"

# Setting GRUB ...
sed -ri 's/GRUB_TIMEOUT=5/GRUB_TIMEOUT=1/' /mnt/etc/default/grub
sed -ri 's/^#GRUB_TERMINAL_OUTPUT/GRUB_TERMINAL_OUTPUT/' /mnt/etc/default/grub
sed -ri "s/^GRUB_CMDLINE_LINUX_DEFAULT.*/GRUB_CMDLINE_LINUX_DEFAULT=\"net.ifnames=0 biosdevname=0 console=ttyS0 earlyprint=serial,ttyS0,keep loglevel=7 nomodeset audit=0\"/g" /mnt/etc/default/grub
sed -ri 's/^#\?GRUB_DISABLE_OS_PROBER=.*/GRUB_DISABLE_OS_PROBER=true/' /mnt/etc/default/grub

# Setting Bootloader
if [ "\${uefi}" = "true" ]; then
  mkdir -p /mnt/sys/firmware/efi/efivars
  mount --rbind /sys/firmware/efi/efivars /mnt/sys/firmware/efi/efivars
  chroot /mnt grub-install --efi-directory=/boot/efi --recheck --bootloader-id=GRUB
  chroot /mnt efibootmgr
  umount /mnt/sys/firmware/efi/efivars
else
  chroot /mnt grub-install --recheck  ${disk}
fi

#chroot /mnt update-grub
chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg

# FIX!!! :  Weak EFI implementation only recognizes the fallback bootloader
[ -d '/mnt/boot/efi/EFI/GRUB' ] && {
    mkdir -p /mnt/boot/efi/EFI/BOOT
    cp /mnt/boot/efi/EFI/GRUB/* /mnt/boot/efi/EFI/BOOT
}
sync

# All done !!!
swapoff /mnt/swap/swapfile
for mountpoint in \$(find /mnt -type d | sort -r); do
  if mountpoint -q "\$mountpoint"; then
    echo "Unmounting \$mountpoint"
    umount -l "\$mountpoint"
  fi
done

sync
trap - EXIT
reboot -f
EOF

  chmod 0755 ${sim_root}/init
}

function sim::create_ramos(){

  sim::cleanup_exit
  trap 'sim::cleanup_warp_exit; exit $?' ERR
  trap 'sim::cleanup_warp_exit' EXIT
  
  sysctl -w kernel.panic=10  > /dev/null 2>&1 && sim::log "[*] Successfully set kernel.panic to 10"
  sysctl -w kernel.sysrq=1  > /dev/null 2>&1 && sim::log "[*] Successfully enabled kernel.sysrq"
   
  sim::log "[*] Creating workspace in '${sim_root}'..."
  mkdir -p "${sim_root}"
  
  sim::log "[*] Mounting temporary rootfs..."
  mount -t tmpfs  -o size=100%  mid "${sim_root}"
  
  sim::_download_ramos_and_extract
  sim::copy_important_config
  sim::install_ramos_packages
  sim::inject_init
  
  swapoff -a;losetup -D || true
  sim::log '[*] Now you will enter the installation process.'
	sim::log '[*] Machine processes with poor performance will be very slow!'
	sim::log "[*] You can try logging in with root and ${password} to check the situation..."
	sleep 1;trap - ERR;trap - EXIT
	systemctl switch-root ${sim_root} /init
}

function sim::hello_world() {
    sim::log '**************************************************************'
    sim::log '                      License: BSD 3'
    sim::log '            Written By: https://github.com/tanbi-org'
    sim::log '**************************************************************'
    sim::log "[*] e.g : --lts --dhcp --pwd ${password} --mirror"
    sim::log "Machine: ${machine_warp:-N/A} Uefi: ${uefi:-N/A} Version: ${ver:-N/A}"
    sim::log "Dhcp: ${dhcp:-N/A}  Mirror: $mirror"
    sim::log 'If you use the --dhcp please make sure your VM supports it !!!'
    sim::log '**************************************************************'
}

function sim::parse_arguments() {
  while [ $# -gt 0 ]; do
    case $1 in
			--mirror)
				mirror="$2"
				shift
				;;
			--pwd)
				password="$2"
				shift
				;;
			--lts)
				ver="linux-lts"
				;;
			--dhcp)
				dhcp='true'
				;;
			*)
				sim::fatal "Unsupported parameters: $1"
		esac
		shift
	done
	
	sim::hello_world
  read -r -p "${1:-[!] This operation will clear all data. Are you sure you want to continue? [y/N]} " _confirm
  case "$_confirm" in [yY][eE][sS]|[yY]) true ;; *) false ;; esac
  
}

if sim::parse_arguments "$@" ; then
  sim::create_ramos
  exit 1
else
  sim::log '[!] Congratulations! You win!'
  sim::log '[!] Oops! Did you mean "goodbye"? Don’t worry, installations can be tricky! 😂'
  sim::log '[!] Maybe try again with different arguments and see what happens?'
  exit 1
fi

