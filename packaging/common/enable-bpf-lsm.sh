#!/bin/sh
set -eu

distribution=${1:-}
root=${MEMSPY_BOOT_ROOT:-}
lsm_file="$root/sys/kernel/security/lsm"
cmdline_file="$root/proc/cmdline"

fail()
{
    echo "MemSpy installer: $*" >&2
    exit 3
}

has_bpf()
{
    case ",$1," in
        *,bpf,*) return 0 ;;
        *) return 1 ;;
    esac
}

with_bpf()
{
    list=$1
    if has_bpf "$list"; then
        printf '%s\n' "$list"
    elif [ -n "$list" ]; then
        printf '%s,bpf\n' "$list"
    else
        printf '%s\n' bpf
    fi
}

replace_lsm_argument()
{
    input=$1
    list=$2
    output=
    replaced=false

    for argument in $input; do
        case "$argument" in
            lsm=*)
                argument="lsm=$list"
                replaced=true
                ;;
        esac
        output="${output}${output:+ }$argument"
    done
    if [ "$replaced" = false ]; then
        output="${output}${output:+ }lsm=$list"
    fi
    printf '%s\n' "$output"
}

regenerate_grub()
{
    case "$distribution" in
        ubuntu|debian)
            command -v update-grub >/dev/null 2>&1 || return 1
            update-grub
            ;;
        fedora)
            command -v grub2-mkconfig >/dev/null 2>&1 || return 1
            grub2-mkconfig -o "$root/boot/grub2/grub.cfg"
            ;;
        arch)
            command -v grub-mkconfig >/dev/null 2>&1 || return 1
            grub-mkconfig -o "$root/boot/grub/grub.cfg"
            ;;
        *) return 1 ;;
    esac
}

configure_grub_defaults()
{
    config="$root/etc/default/grub"
    key=GRUB_CMDLINE_LINUX_DEFAULT
    line=$(grep "^$key=" "$config" | tail -n 1 || true)
    if [ -z "$line" ]; then
        key=GRUB_CMDLINE_LINUX
        line=$(grep "^$key=" "$config" | tail -n 1 || true)
    fi
    if [ -n "$line" ]; then
        value=${line#*=}
        case "$value" in
            \"*\") value=${value#\"}; value=${value%\"} ;;
            *) fail "$key in $config must use double quotes" ;;
        esac
    else
        key=GRUB_CMDLINE_LINUX_DEFAULT
        value=
    fi
    case "$value" in
        *\"*) fail "cannot safely update $key in $config" ;;
    esac
    updated=$(replace_lsm_argument "$value" "$merged_lsm")
    backup=$(mktemp)
    cp -p "$config" "$backup"
    awk -v key="$key" -v replacement="$key=\"$updated\"" '
        BEGIN { replaced = 0 }
        index($0, key "=") == 1 { print replacement; replaced = 1; next }
        { print }
        END { if (!replaced) print replacement }
    ' "$config" >"$config.memspy-new"
    chmod --reference="$config" "$config.memspy-new"
    chown --reference="$config" "$config.memspy-new"
    mv "$config.memspy-new" "$config"
    if ! regenerate_grub; then
        cp -p "$backup" "$config"
        rm -f "$backup"
        fail "could not regenerate GRUB; restored $config"
    fi
    rm -f "$backup"
}

configure_systemd_boot()
{
    config="$root/etc/kernel/cmdline"
    value=$(cat "$config")
    updated=$(replace_lsm_argument "$value" "$merged_lsm")
    backup=$(mktemp)
    cp -p "$config" "$backup"
    printf '%s\n' "$updated" >"$config"
    if ! kernel-install add-all; then
        cp -p "$backup" "$config"
        rm -f "$backup"
        fail "kernel-install failed; restored $config"
    fi
    rm -f "$backup"
}

case "$distribution" in
    ubuntu|debian|fedora|arch) ;;
    *) fail "unsupported distribution '$distribution' for automatic BPF LSM setup" ;;
esac
test -r "$lsm_file" || fail "cannot read $lsm_file"
active_lsm=$(tr -d '[:space:]' <"$lsm_file")
if has_bpf "$active_lsm"; then
    echo "BPF LSM is already active"
    exit 0
fi

configured_lsm=
if [ -r "$cmdline_file" ]; then
    for argument in $(cat "$cmdline_file"); do
        case "$argument" in
            lsm=*) configured_lsm=${argument#lsm=} ;;
        esac
    done
fi
test -n "$configured_lsm" || configured_lsm=$active_lsm
merged_lsm=$(with_bpf "$configured_lsm")

if [ "$distribution" = fedora ] && command -v grubby >/dev/null 2>&1; then
    grubby --update-kernel=ALL --remove-args=lsm --args="lsm=$merged_lsm" || \
        fail "grubby could not update the kernel command line"
elif [ -f "$root/etc/default/grub" ]; then
    configure_grub_defaults
elif [ -f "$root/etc/kernel/cmdline" ] && command -v kernel-install >/dev/null 2>&1; then
    configure_systemd_boot
else
    fail "could not identify a supported GRUB or systemd-boot configuration"
fi

echo "BPF LSM enabled for the next boot — reboot required"
