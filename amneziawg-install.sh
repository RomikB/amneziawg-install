#!/bin/bash

# AmneziaWG server installer
# https://github.com/romikb/amneziawg-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"

function isRoot() {
    if [ "${EUID}" -ne 0 ]; then
        echo "You need to run this script as root"
        exit 1
    fi
}

function checkVirt() {
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        echo "OpenVZ is not supported"
        exit 1
    fi

    if [ "$(systemd-detect-virt)" == "lxc" ]; then
        echo "LXC is not supported (yet)."
        echo "WireGuard can technically run in an LXC container,"
        echo "but the kernel module has to be installed on the host,"
        echo "the container has to be run with some specific parameters"
        echo "and only the tools need to be installed in the container."
        exit 1
    fi
}

function checkOS() {
    source /etc/os-release

    OS="${ID}"

    case "$OS" in
    "debian" | "raspbian")
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [[ ! "$MAJOR_VERSION" =~ ^[0-9]+$ || "$MAJOR_VERSION" -lt 12 ]]; then
            echo "Your version of Debian ($VERSION_ID) is not supported. Please use Debian 12 Bookworm or later."
            exit 1
        fi
        OS="debian" #overwrite if raspbian
        ;;
    "ubuntu")
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [[ ! "$MAJOR_VERSION" =~ ^[0-9]+$ || "$MAJOR_VERSION" -lt 22 ]]; then
            echo "Your version of Ubuntu ($VERSION_ID) is not supported. Please use Ubuntu 22.04 or later."
            exit 1
        fi
        ;;
    "fedora")
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [[ ! "$MAJOR_VERSION" =~ ^[0-9]+$ || "$MAJOR_VERSION" -lt 43 ]]; then
            echo "Your version of Fedora ($VERSION_ID) is not supported. Please use Fedora 43 or later."
            exit 1
        fi
        ;;
    "centos" | "almalinux" | "rocky" | "rhel")
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d'.' -f1)
        if [[ ! "$MAJOR_VERSION" =~ ^[0-9]+$ || "$MAJOR_VERSION" -lt 9 ]]; then
            echo "Your version of $OS ($VERSION_ID) is not supported. Please use $OS 9 or later."
            exit 1
        fi
        ;;
    *)
        echo "Looks like you are not running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Rocky Linux or RHEL system."
        exit 1
        ;;
    esac
}

function getHomeDirForClient() {
    local CLIENT_NAME=$1

    if [ -z "${CLIENT_NAME}" ]; then
        echo "Error: getHomeDirForClient() requires a client name as argument"
        exit 1
    fi

    # Home directory of the user, where the client configuration will be written
    if [ -e "/home/${CLIENT_NAME}" ]; then
        # if $1 is a user name
        HOME_DIR="/home/${CLIENT_NAME}"
    elif [ "${SUDO_USER}" ]; then
        # if not, use SUDO_USER
        if [ "${SUDO_USER}" == "root" ]; then
            # If running sudo as root
            HOME_DIR="/root"
        else
            HOME_DIR="/home/${SUDO_USER}"
        fi
    else
        # if not SUDO_USER, use /root
        HOME_DIR="/root"
    fi

    echo "$HOME_DIR"
}

function getDirForClientConfig() {
    if [[ ${STORE_CLIENT} == 'y' ]]; then
        CONFIG_DIR=${AMNEZIAWG_DIR}
    else
        CONFIG_DIR=$(getHomeDirForClient $1)
    fi
    echo "$CONFIG_DIR"
}

function initialCheck() {
    isRoot
    checkVirt
    checkOS
}

function readJminAndJmax() {
    SERVER_AWG_JMIN=0
    SERVER_AWG_JMAX=0
    until [[ ${SERVER_AWG_JMIN} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMIN} >= 1 )) && (( ${SERVER_AWG_JMIN} <= 1280 )); do
        read -rp "Server AmneziaWG Jmin [1-1280]: " -e -i 40 SERVER_AWG_JMIN
    done
    until [[ ${SERVER_AWG_JMAX} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMAX} >= 1 )) && (( ${SERVER_AWG_JMAX} <= 1280 )); do
        read -rp "Server AmneziaWG Jmax [1-1280]: " -e -i 70 SERVER_AWG_JMAX
    done
}

function generateSParams() {
    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        RANDOM_AWG_S1=$(shuf -i12-150 -n1)
        RANDOM_AWG_S2=${RANDOM_AWG_S1}
        RANDOM_AWG_S3=${RANDOM_AWG_S1}
        RANDOM_AWG_S4=${RANDOM_AWG_S1}
    else
        RANDOM_AWG_S1=$(shuf -i15-150 -n1)
        RANDOM_AWG_S2=$(shuf -i15-150 -n1)
        RANDOM_AWG_S3=""
        RANDOM_AWG_S4=""
    fi
}

function readSParams() {
    SERVER_AWG_S1=0
    SERVER_AWG_S2=0
    local min_s=15
    local default_s2=${RANDOM_AWG_S2}
    local default_s3=${RANDOM_AWG_S3}
    local default_s4=${RANDOM_AWG_S4}
    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        min_s=12
        if [[ "${SERVER_AWG_RANDOM_TRAILERS}" == "y" ]]; then
            default_s2=${RANDOM_AWG_S1}
            default_s3=${RANDOM_AWG_S1}
            default_s4=${RANDOM_AWG_S1}
        fi
    fi
    until [[ ${SERVER_AWG_S1} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S1 >= min_s && SERVER_AWG_S1 <= 150 )); do
        read -rp "Server AmneziaWG S1 [${min_s}-150]: " -e -i ${RANDOM_AWG_S1} SERVER_AWG_S1
    done
    if [[ "${AWG_VERSION}" == "3.1" && "${SERVER_AWG_RANDOM_TRAILERS}" == "y" ]]; then
        default_s2=${SERVER_AWG_S1}
        default_s3=${SERVER_AWG_S1}
        default_s4=${SERVER_AWG_S1}
    fi
    until [[ ${SERVER_AWG_S2} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S2 >= min_s && SERVER_AWG_S2 <= 150 )); do
        read -rp "Server AmneziaWG S2 [${min_s}-150]: " -e -i ${default_s2} SERVER_AWG_S2
    done
    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        SERVER_AWG_S3=0
        SERVER_AWG_S4=0
        until [[ ${SERVER_AWG_S3} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S3 >= 12 && SERVER_AWG_S3 <= 150 )); do
            read -rp "Server AmneziaWG S3 [12-150]: " -e -i ${default_s3} SERVER_AWG_S3
        done
        until [[ ${SERVER_AWG_S4} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S4 >= 12 && SERVER_AWG_S4 <= 150 )); do
            read -rp "Server AmneziaWG S4 [12-150]: " -e -i ${default_s4} SERVER_AWG_S4
        done
    fi
}

function validateHValue() {
    local val="$1"
    local min_val="$2"
    local max_val=4294967295

    if [[ "$val" =~ ^[0-9]+$ ]]; then
        if (( val >= min_val && val <= max_val )); then
            echo "$val $val"
            return 0
        fi
    elif [[ "$val" =~ ^([0-9]+)-([0-9]+)$ ]]; then
        local low="${BASH_REMATCH[1]}"
        local high="${BASH_REMATCH[2]}"
        if (( low >= min_val && high <= max_val && low <= high )); then
            echo "$low $high"
            return 0
        fi
    fi
    return 1
}

function checkHOverlap() {
    local -a h_vals=("$1" "$2" "$3" "$4")
    local -a lows=()
    local -a highs=()
    local min_val="${5:-1}"

    for i in 0 1 2 3; do
        local res
        res=$(validateHValue "${h_vals[$i]}" "$min_val") || return 1
        read -r l h <<< "$res"
        lows[$i]="$l"
        highs[$i]="$h"
    done

    for ((i = 0; i < 4; i++)); do
        for ((j = i + 1; j < 4; j++)); do
            if (( lows[i] <= highs[j] && highs[i] >= lows[j] )); then
                return 2
            fi
        done
    done
    return 0
}

function generateH1AndH2AndH3AndH4() {
    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        RANDOM_AWG_H1=1
        RANDOM_AWG_H2=2
        RANDOM_AWG_H3=3
        RANDOM_AWG_H4=4
    else
        RANDOM_AWG_H1=$(shuf -i5-2147483647 -n1)
        RANDOM_AWG_H2=$(shuf -i5-2147483647 -n1)
        RANDOM_AWG_H3=$(shuf -i5-2147483647 -n1)
        RANDOM_AWG_H4=$(shuf -i5-2147483647 -n1)
    fi
}

function readH1AndH2AndH3AndH4() {
    local min_h=5
    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        min_h=1
    fi

    echo ""
    echo "H1-H4 obfuscation: enter single numbers or ranges (e.g. 100-200) without overlap."
    while true; do
        SERVER_AWG_H1=""
        SERVER_AWG_H2=""
        SERVER_AWG_H3=""
        SERVER_AWG_H4=""

        until [[ -n "${SERVER_AWG_H1}" ]] && validateHValue "${SERVER_AWG_H1}" "${min_h}" >/dev/null; do
            read -rp "Server AmneziaWG H1 [${min_h}-4294967295]: " -e -i "${RANDOM_AWG_H1}" SERVER_AWG_H1
        done
        until [[ -n "${SERVER_AWG_H2}" ]] && validateHValue "${SERVER_AWG_H2}" "${min_h}" >/dev/null; do
            read -rp "Server AmneziaWG H2 [${min_h}-4294967295]: " -e -i "${RANDOM_AWG_H2}" SERVER_AWG_H2
        done
        until [[ -n "${SERVER_AWG_H3}" ]] && validateHValue "${SERVER_AWG_H3}" "${min_h}" >/dev/null; do
            read -rp "Server AmneziaWG H3 [${min_h}-4294967295]: " -e -i "${RANDOM_AWG_H3}" SERVER_AWG_H3
        done
        until [[ -n "${SERVER_AWG_H4}" ]] && validateHValue "${SERVER_AWG_H4}" "${min_h}" >/dev/null; do
            read -rp "Server AmneziaWG H4 [${min_h}-4294967295]: " -e -i "${RANDOM_AWG_H4}" SERVER_AWG_H4
        done

        local overlap_code=0
        checkHOverlap "${SERVER_AWG_H1}" "${SERVER_AWG_H2}" "${SERVER_AWG_H3}" "${SERVER_AWG_H4}" "${min_h}" || overlap_code=$?

        if [[ "${overlap_code}" -eq 0 ]]; then
            break
        elif [[ "${overlap_code}" -eq 2 ]]; then
            echo "AmneziaWG requires H1, H2, H3 and H4 values or ranges not to overlap. Please re-enter."
        else
            echo "AmneziaWG requires valid H parameters within [${min_h}-4294967295]. Please re-enter."
        fi
    done
}

function validateIParam() {
    local val="$1"
    [[ -z "$val" ]] && return 1
    local remaining="$val"
    local tag_regex="^(<[bB] +0[xX]([0-9a-fA-F]{2})+>|<[rR] +[1-9][0-9]*>|<[rR][dD] +[1-9][0-9]*>|<[rR][cC] +[1-9][0-9]*>|<[tT]>)"
    while [[ -n "$remaining" ]]; do
        if [[ "$remaining" =~ $tag_regex ]]; then
            local matched="${BASH_REMATCH[0]}"
            remaining="${remaining:${#matched}}"
        else
            return 1
        fi
    done
    return 0
}

function readIParams() {
    SERVER_AWG_I1=""
    SERVER_AWG_I2=""
    SERVER_AWG_I3=""
    SERVER_AWG_I4=""
    SERVER_AWG_I5=""

    echo ""
    echo "Custom Protocol Signature (CPS) decoy packets (I1-I5):"
    echo "Packets sent before handshake to mimic legitimate protocols (e.g. QUIC, DNS)."
    echo "Supported tags:"
    echo "  <b 0xHEX>  - static hex bytes (even number of hex digits, e.g. <b 0xd100000001>)"
    echo "  <r SIZE>   - random bytes (e.g. <r 64>)"
    echo "  <rd SIZE>  - random digits 0-9 (e.g. <rd 10>)"
    echo "  <rc SIZE>  - random chars a-zA-Z (e.g. <rc 8>)"
    echo "  <t>        - 4-byte UNIX timestamp"
    echo "Leave empty (press Enter) to skip or finish the sequence."

    local i
    for i in 1 2 3 4 5; do
        local input=""
        while true; do
            read -rp "AmneziaWG I${i} [optional, Enter to finish]: " -e input
            input=$(echo "${input}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [[ -z "${input}" ]]; then
                return 0
            fi
            if validateIParam "${input}"; then
                case "${i}" in
                    1) SERVER_AWG_I1="${input}" ;;
                    2) SERVER_AWG_I2="${input}" ;;
                    3) SERVER_AWG_I3="${input}" ;;
                    4) SERVER_AWG_I4="${input}" ;;
                    5) SERVER_AWG_I5="${input}" ;;
                esac
                break
            else
                echo "Invalid syntax for I${i}! Allowed tags: <b 0xHEX>, <r SIZE>, <rd SIZE>, <rc SIZE>, <t>."
                echo "Example: <b 0xd100000001><rc 8><t><r 50> or <r 64>. Press Enter without input to finish."
            fi
        done
    done
}

function installQuestions() {
    echo "AmneziaWG server installer (https://github.com/romikb/amneziawg-install)"
    echo ""
    echo "I need to ask you a few questions before starting the setup."
    echo "You can keep the default options and just press enter if you are ok with them."
    echo ""

    # Reset interactive variables
    SERVER_PUB_IP=""
    SERVER_PORT=""
    DNS_CHOICE=""
    AWG_VERSION=""
    AWG_VERSION_CHOICE=""
    SERVER_AWG_MTU=""
    SERVER_AWG_HPK=""
    SERVER_AWG_CPA=""
    SERVER_AWG_RANDOM_TRAILERS=""
    SERVER_AWG_DISABLE_COOKIES=""
    SERVER_AWG_I1=""
    SERVER_AWG_I2=""
    SERVER_AWG_I3=""
    SERVER_AWG_I4=""
    SERVER_AWG_I5=""
    SERVER_AWG_S3=""
    SERVER_AWG_S4=""
    ADVANCED_SETTINGS=""
    USE_IPV6=""
    SERVER_PUB_NIC=""
    SERVER_AWG_NIC=""
    SERVER_AWG_IPV4=""
    SERVER_AWG_IPV6=""
    STORE_CLIENT=""
    USE_NFTABLES=""
    ALLOWED_IPS=""
    KEEPALIVE=""

    # Detect public IPv4 or IPv6 address and pre-fill for the user
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    read -rp "Public IPv4 or IPv6 address or domain: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

    # Generate random number within private ports range
    RANDOM_PORT=$(shuf -i49152-65535 -n1)
    until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
        read -rp "Server AmneziaWG port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
    done

    # Select DNS resolver
    echo ""
    echo "Select a DNS resolver for the clients:"
    echo "   1) Cloudflare (1.1.1.1, 1.0.0.1) [Recommended]"
    echo "   2) AdGuard DNS (blocks ads and trackers)"
    echo "   3) Google DNS (8.8.8.8, 8.8.4.4)"
    echo "   4) Custom DNS"
    until [[ ${DNS_CHOICE} =~ ^[1-4]$ ]]; do
        read -rp "DNS resolver [1-4]: " -e -i 1 DNS_CHOICE
    done
    case "${DNS_CHOICE}" in
    1)
        CLIENT_IPV4_DNS_1="1.1.1.1"
        CLIENT_IPV4_DNS_2="1.0.0.1"
        CLIENT_IPV6_DNS_1="2606:4700:4700::1111"
        CLIENT_IPV6_DNS_2="2606:4700:4700::1001"
        ;;
    2)
        CLIENT_IPV4_DNS_1="94.140.14.14"
        CLIENT_IPV4_DNS_2="94.140.15.15"
        CLIENT_IPV6_DNS_1="2a10:50c0::ad1:ff"
        CLIENT_IPV6_DNS_2="2a10:50c0::ad2:ff"
        ;;
    3)
        CLIENT_IPV4_DNS_1="8.8.8.8"
        CLIENT_IPV4_DNS_2="8.8.4.4"
        CLIENT_IPV6_DNS_1="2001:4860:4860::8888"
        CLIENT_IPV6_DNS_2="2001:4860:4860::8844"
        ;;
    4)
        until [[ ${CLIENT_IPV4_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
            read -rp "First IPv4 DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_IPV4_DNS_1
        done
        until [[ ${CLIENT_IPV4_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
            read -rp "Second IPv4 DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_IPV4_DNS_2
        done
        ;;
    esac

    # Select AmneziaWG protocol version
    echo ""
    echo "Select AmneziaWG protocol version:"
    echo "   1) AmneziaWG 3.1 (Recommended / Maximum anti-DPI protection) [Default]"
    echo "   2) AmneziaWG 2.0 (Compatibility with KeeneticOS / OpenWrt / routers)"
    echo "   3) AmneziaWG 1.0 (Legacy)"
    until [[ ${AWG_VERSION_CHOICE} =~ ^[1-3]$ ]]; do
        read -rp "Protocol version [1-3]: " -e -i 1 AWG_VERSION_CHOICE
    done
    case "${AWG_VERSION_CHOICE}" in
    1) AWG_VERSION="3.1" ;;
    2) AWG_VERSION="2.0" ;;
    3) AWG_VERSION="1.0" ;;
    esac

    # Advanced settings toggle
    echo ""
    until [[ ${ADVANCED_SETTINGS} =~ ^[yn]$ ]]; do
        read -rp "Customize advanced settings (IPv6, interface, firewall, obfuscation)? [y/n]: " -e -i n ADVANCED_SETTINGS
        ADVANCED_SETTINGS=${ADVANCED_SETTINGS,,}
    done

    # Detect public interface
    SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
    if [[ -z ${SERVER_NIC} ]]; then
        SERVER_NIC="$(ip -6 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
    fi

    # Pre-generate base obfuscation parameters
    RANDOM_AWG_JC=$(shuf -i4-8 -n1)
    generateSParams
    while (( ${RANDOM_AWG_S1} + 56 == ${RANDOM_AWG_S2} )); do
        generateSParams
    done
    generateH1AndH2AndH3AndH4
    if [[ "${AWG_VERSION}" != "3.1" ]]; then
        while ! checkHOverlap "${RANDOM_AWG_H1}" "${RANDOM_AWG_H2}" "${RANDOM_AWG_H3}" "${RANDOM_AWG_H4}" "5" >/dev/null 2>&1; do
            generateH1AndH2AndH3AndH4
        done
    fi

    if [[ ${ADVANCED_SETTINGS} == 'y' ]]; then
        echo ""
        echo "--- Advanced configuration ---"

        DEFAULT_MTU=1360
        if [[ "${AWG_VERSION}" != "3.1" ]]; then
            DEFAULT_MTU=1420
        fi
        until [[ ${SERVER_AWG_MTU} =~ ^[0-9]+$ ]] && (( SERVER_AWG_MTU >= 576 && SERVER_AWG_MTU <= 1500 )); do
            read -rp "AmneziaWG MTU [576-1500]: " -e -i "${DEFAULT_MTU}" SERVER_AWG_MTU
        done

        until [[ ${USE_IPV6} =~ ^[yn]$ ]]; do
            read -rp "Do you want to use IPv6? [y/n]: " -e -i n USE_IPV6
            USE_IPV6=${USE_IPV6,,}
        done

        until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
            read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
        done

        until [[ ${SERVER_AWG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_AWG_NIC} -lt 16 ]]; do
            read -rp "AmneziaWG interface name: " -e -i awg0 SERVER_AWG_NIC
        done

        until [[ ${SERVER_AWG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
            read -rp "Server AmneziaWG IPv4: " -e -i 10.66.66.1 SERVER_AWG_IPV4
        done

        if [[ ${USE_IPV6} == 'y' ]]; then
            until [[ ${SERVER_AWG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
                read -rp "Server AmneziaWG IPv6: " -e -i fd42:42:42::1 SERVER_AWG_IPV6
            done

            if [[ ${DNS_CHOICE} == '4' ]]; then
                until [[ ${CLIENT_IPV6_DNS_1} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
                    read -rp "First IPv6 DNS resolver to use for the clients: " -e -i 2606:4700:4700::1111 CLIENT_IPV6_DNS_1
                done

                until [[ ${CLIENT_IPV6_DNS_2} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
                    read -rp "Second IPv6 DNS resolver to use for the clients (optional): " -e -i 2606:4700:4700::1001 CLIENT_IPV6_DNS_2
                done
            fi
        fi

        until [[ ${STORE_CLIENT} =~ ^[yn]$ ]]; do
            read -rp "Store client config file at ${AMNEZIAWG_DIR}? [y/n]: " -e -i y STORE_CLIENT
            STORE_CLIENT=${STORE_CLIENT,,}
        done

        until [[ ${USE_NFTABLES} =~ ^[yn]$ ]]; do
            read -rp "Use nftables instead of iptables? [y/n]: " -e -i y USE_NFTABLES
            USE_NFTABLES=${USE_NFTABLES,,}
        done

        POSSIBLE_ALLOWED_IPS="0.0.0.0/0"
        if [[ ${USE_IPV6} == 'y' ]]; then
            POSSIBLE_ALLOWED_IPS="${POSSIBLE_ALLOWED_IPS}, ::/0"
        fi
        until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
            read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i "$POSSIBLE_ALLOWED_IPS" ALLOWED_IPS
        if [[ ${ALLOWED_IPS} == "" ]]; then
            ALLOWED_IPS="$POSSIBLE_ALLOWED_IPS"
        fi
        done

        # Keepalive interval
        until [[ ${KEEPALIVE} =~ ^[0-9]+$ ]] && [ "${KEEPALIVE}" -ge 0 ] && [ "${KEEPALIVE}" -le 65535 ]; do
            read -rp "Keepalive interval [0-65535]: " -e -i 0 KEEPALIVE
        done

        # Jc
        until [[ ${SERVER_AWG_JC} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JC} >= 1 )) && (( ${SERVER_AWG_JC} <= 128 )); do
            read -rp "Server AmneziaWG Jc [1-128]: " -e -i ${RANDOM_AWG_JC} SERVER_AWG_JC
        done

        # Jmin && Jmax
        readJminAndJmax
        until [ "${SERVER_AWG_JMIN}" -le "${SERVER_AWG_JMAX}" ]; do
            echo "AmneziaWG requires Jmin <= Jmax"
            readJminAndJmax
        done

        if [[ "${AWG_VERSION}" == "3.1" ]]; then
            echo ""
            echo "HeaderProtectionKey encrypts packet headers using ChaCha20 (AmneziaWG 3.1+)."
            echo "Leave 'auto' to automatically generate via 'awg genkey' during installation,"
            echo "or provide a custom 32-byte Base64 key."
            until [[ "${SERVER_AWG_HPK}" == "auto" || "${SERVER_AWG_HPK}" =~ ^[A-Za-z0-9+/]{43}=$ || "${SERVER_AWG_HPK}" =~ ^[A-Za-z0-9+/]{44}$ ]]; do
                read -rp "HeaderProtectionKey [auto or 32-byte base64]: " -e -i auto SERVER_AWG_HPK
            done

            until [[ "${SERVER_AWG_CPA}" =~ ^[0-9]+(-[0-9]+)?$ ]]; do
                read -rp "ContentPaddingAddition [e.g. 16-64]: " -e -i "16-64" SERVER_AWG_CPA
            done

            echo ""
            echo "RandomTrailers appends random-length padding to packets to disrupt size profiling (AmneziaWG 3.1+)."
            until [[ ${SERVER_AWG_RANDOM_TRAILERS} =~ ^[yn]$ ]]; do
                read -rp "Enable RandomTrailers? [y/n]: " -e -i y SERVER_AWG_RANDOM_TRAILERS
                SERVER_AWG_RANDOM_TRAILERS=${SERVER_AWG_RANDOM_TRAILERS,,}
            done

            echo ""
            echo "DisableCookies disables handshake cookie replies to evade active DPI probing (AmneziaWG 3.1+)."
            until [[ ${SERVER_AWG_DISABLE_COOKIES} =~ ^[yn]$ ]]; do
                read -rp "Enable DisableCookies? [y/n]: " -e -i y SERVER_AWG_DISABLE_COOKIES
                SERVER_AWG_DISABLE_COOKIES=${SERVER_AWG_DISABLE_COOKIES,,}
            done
        else
            SERVER_AWG_HPK=""
            SERVER_AWG_CPA=""
            SERVER_AWG_S3=""
            SERVER_AWG_S4=""
            SERVER_AWG_RANDOM_TRAILERS="n"
            SERVER_AWG_DISABLE_COOKIES="n"
        fi

        # S1 && S2 (and S3 && S4 for AWG 3.1)
        if [[ "${AWG_VERSION}" == "3.1" && "${SERVER_AWG_RANDOM_TRAILERS}" == "y" ]]; then
            echo ""
            echo "Note: When RandomTrailers is enabled, AmneziaWG recommends setting S1 = S2 = S3 = S4."
        fi
        readSParams
        while (( ${SERVER_AWG_S1} + 56 == ${SERVER_AWG_S2} )); do
            echo "AmneziaWG requires S1 + 56 <> S2"
            readSParams
        done

        # H1 && H2 && H3 && H4 (supports uint32 and intervals min-max)
        readH1AndH2AndH3AndH4

        # I1-I5 Custom Protocol Signature (CPS) for AWG 3.1 and 2.0
        if [[ "${AWG_VERSION}" != "1.0" ]]; then
            readIParams
        else
            SERVER_AWG_I1=""
            SERVER_AWG_I2=""
            SERVER_AWG_I3=""
            SERVER_AWG_I4=""
            SERVER_AWG_I5=""
        fi
    else
        # Standard mode automatic defaults
        USE_IPV6="n"
        SERVER_PUB_NIC="${SERVER_NIC:-eth0}"
        SERVER_AWG_NIC="awg0"
        SERVER_AWG_IPV4="10.66.66.1"
        STORE_CLIENT="y"
        USE_NFTABLES="y"
        ALLOWED_IPS="0.0.0.0/0"
        KEEPALIVE=0
        SERVER_AWG_JC=${RANDOM_AWG_JC}
        SERVER_AWG_JMIN=40
        SERVER_AWG_JMAX=70

        if [[ "${AWG_VERSION}" == "3.1" ]]; then
            SERVER_AWG_MTU=1360
            SERVER_AWG_HPK="auto"
            SERVER_AWG_CPA="16-64"
            SERVER_AWG_RANDOM_TRAILERS="y"
            SERVER_AWG_DISABLE_COOKIES="y"
            SERVER_AWG_S1=${RANDOM_AWG_S1}
            SERVER_AWG_S2=${RANDOM_AWG_S1}
            SERVER_AWG_S3=${RANDOM_AWG_S1}
            SERVER_AWG_S4=${RANDOM_AWG_S1}
            SERVER_AWG_H1=1
            SERVER_AWG_H2=2
            SERVER_AWG_H3=3
            SERVER_AWG_H4=4
        else
            SERVER_AWG_MTU=1420
            SERVER_AWG_HPK=""
            SERVER_AWG_CPA=""
            SERVER_AWG_RANDOM_TRAILERS="n"
            SERVER_AWG_DISABLE_COOKIES="n"
            SERVER_AWG_S1=${RANDOM_AWG_S1}
            SERVER_AWG_S2=${RANDOM_AWG_S2}
            SERVER_AWG_S3=""
            SERVER_AWG_S4=""
            SERVER_AWG_H1=${RANDOM_AWG_H1}
            SERVER_AWG_H2=${RANDOM_AWG_H2}
            SERVER_AWG_H3=${RANDOM_AWG_H3}
            SERVER_AWG_H4=${RANDOM_AWG_H4}
        fi
        SERVER_AWG_I1=""
        SERVER_AWG_I2=""
        SERVER_AWG_I3=""
        SERVER_AWG_I4=""
        SERVER_AWG_I5=""
    fi

    echo ""
    echo "Okay, that was all I needed. Ready to setup your AmneziaWG server now."
}

function installAmneziaWG() {
    # Run setup questions first
    installQuestions

    if [[ ${USE_NFTABLES} == 'y' ]]; then NF_PACKAGE="nftables"; else NF_PACKAGE="iptables"; fi

    # Install AmneziaWG tools and module
    if [[ ${OS} == 'ubuntu' ]]; then
        apt-get update
        apt-get install -y software-properties-common "linux-headers-$(uname -r)"
        add-apt-repository -y ppa:amnezia/ppa
        apt-get update
        apt-get install -y amneziawg amneziawg-tools qrencode ${NF_PACKAGE}
    elif [[ ${OS} == 'debian' ]]; then
        apt-get update
        apt-get install -y "linux-headers-$(uname -r)" curl gnupg

        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d'.' -f1)
        case "$MAJOR_VERSION" in
            12) UBUNTU_SUITE="jammy" ;;
            *)  UBUNTU_SUITE="noble" ;;
        esac

        install -d -m 755 /etc/apt/keyrings
        curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x57290828" | gpg --dearmor --yes -o "/etc/apt/keyrings/amneziawg-keyring.gpg"
        echo "Types: deb deb-src
URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu
Suites: ${UBUNTU_SUITE}
Components: main
Signed-By: /etc/apt/keyrings/amneziawg-keyring.gpg
" > "/etc/apt/sources.list.d/amneziawg.sources"
        apt-get update
        apt-get install -y amneziawg amneziawg-tools qrencode ${NF_PACKAGE}
    elif [[ ${OS} == 'fedora' ]]; then
        dnf copr enable -y tigro/amneziawg
        dnf install -y amneziawg-kmod amneziawg-tools qrencode bc ${NF_PACKAGE}
    elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'rhel' ]]; then
        dnf install -y dnf-plugins-core 2>/dev/null || true
        dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager enable crb 2>/dev/null || crb enable 2>/dev/null || true
        dnf install -y epel-release
        dnf copr enable -y tigro/amneziawg
        if [[ ${MAJOR_VERSION} -ge 10 ]]; then
            echo -e "\n${ORANGE}WARNING: Detected Enterprise Linux 10 (${OS} ${VERSION_ID}).${NC}"
            echo -e "${ORANGE}EL 10 package availability and build success depend on the Copr repository author and official kernel source compatibility.${NC}"
            echo -e "${ORANGE}Building kernel module via DKMS (amneziawg-dkms)...${NC}\n"
            dnf install -y amneziawg-dkms amneziawg-tools qrencode ${NF_PACKAGE}
        else
            dnf install -y kmod-amneziawg amneziawg-tools qrencode ${NF_PACKAGE}
        fi
    fi

    SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

    # Deferred generation of HeaderProtectionKey for AWG 3.1
    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        if [[ -z "${SERVER_AWG_HPK}" || "${SERVER_AWG_HPK}" == "auto" ]]; then
            SERVER_AWG_HPK=$(awg genkey)
        fi
    fi

    SERVER_PRIV_KEY=$(awg genkey)
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)

    SERVER_AWG_IPS="SERVER_AWG_IPV4=${SERVER_AWG_IPV4}"

    if [[ "$USE_IPV6" = 'y' ]]; then
        SERVER_AWG_IPS="${SERVER_AWG_IPS}\nSERVER_AWG_IPV6=${SERVER_AWG_IPV6}"
    fi

    # Save AmneziaWG settings
    echo -e "${SERVER_AWG_IPS}
AWG_VERSION=${AWG_VERSION}
SERVER_AWG_MTU=${SERVER_AWG_MTU}
SERVER_AWG_HPK=${SERVER_AWG_HPK}
SERVER_AWG_CPA=${SERVER_AWG_CPA}
SERVER_AWG_RANDOM_TRAILERS=${SERVER_AWG_RANDOM_TRAILERS}
SERVER_AWG_DISABLE_COOKIES=${SERVER_AWG_DISABLE_COOKIES}
SERVER_AWG_I1=\"${SERVER_AWG_I1}\"
SERVER_AWG_I2=\"${SERVER_AWG_I2}\"
SERVER_AWG_I3=\"${SERVER_AWG_I3}\"
SERVER_AWG_I4=\"${SERVER_AWG_I4}\"
SERVER_AWG_I5=\"${SERVER_AWG_I5}\"
SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_AWG_NIC=${SERVER_AWG_NIC}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_IPV4_DNS_1=${CLIENT_IPV4_DNS_1}
CLIENT_IPV4_DNS_2=${CLIENT_IPV4_DNS_2}
CLIENT_IPV6_DNS_1=${CLIENT_IPV6_DNS_1}
CLIENT_IPV6_DNS_2=${CLIENT_IPV6_DNS_2}
STORE_CLIENT=${STORE_CLIENT}
USE_IPV6=${USE_IPV6}
USE_NFTABLES=${USE_NFTABLES}
ALLOWED_IPS=\"${ALLOWED_IPS}\"
KEEPALIVE=${KEEPALIVE}
SERVER_AWG_JC=${SERVER_AWG_JC}
SERVER_AWG_JMIN=${SERVER_AWG_JMIN}
SERVER_AWG_JMAX=${SERVER_AWG_JMAX}
SERVER_AWG_S1=${SERVER_AWG_S1}
SERVER_AWG_S2=${SERVER_AWG_S2}
SERVER_AWG_S3=${SERVER_AWG_S3}
SERVER_AWG_S4=${SERVER_AWG_S4}
SERVER_AWG_H1=${SERVER_AWG_H1}
SERVER_AWG_H2=${SERVER_AWG_H2}
SERVER_AWG_H3=${SERVER_AWG_H3}
SERVER_AWG_H4=${SERVER_AWG_H4}" > "${AMNEZIAWG_DIR}/params"

    # Add server interface
    SERVER_ADDRESS="${SERVER_AWG_IPV4}/24"

    if [[ "$USE_IPV6" = 'y' ]]; then
        SERVER_ADDRESS="${SERVER_ADDRESS}, ${SERVER_AWG_IPV6}/64"
    fi

    echo "[Interface]
Address = ${SERVER_ADDRESS}
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
MTU = ${SERVER_AWG_MTU}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}" >"${SERVER_AWG_CONF}"

    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        echo "S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}
HeaderProtectionKey = ${SERVER_AWG_HPK}
ContentPaddingAddition = ${SERVER_AWG_CPA}" >>"${SERVER_AWG_CONF}"
    else
        echo "H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}" >>"${SERVER_AWG_CONF}"
    fi

    # Append parameters only if they differ from configuration defaults
    if [[ "${SERVER_AWG_RANDOM_TRAILERS}" == "y" ]]; then
        echo "RandomTrailers = on" >>"${SERVER_AWG_CONF}"
    fi

    if [[ "${SERVER_AWG_DISABLE_COOKIES}" == "y" ]]; then
        echo "DisableCookies = on" >>"${SERVER_AWG_CONF}"
    fi

    if systemctl is-active --quiet firewalld 2>/dev/null || pgrep -x firewalld >/dev/null 2>&1; then
        echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_AWG_NIC}
PostUp = firewall-cmd --zone=public --add-port=${SERVER_PORT}/udp" >>"${SERVER_AWG_CONF}"

        echo "PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i ${SERVER_AWG_NIC} -o ${SERVER_PUB_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i ${SERVER_AWG_NIC} -o ${SERVER_PUB_NIC} -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv4 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT" >>"${SERVER_AWG_CONF}"

        if [[ "$USE_IPV6" = 'y' ]]; then
            echo "PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i ${SERVER_AWG_NIC} -o ${SERVER_PUB_NIC} -j ACCEPT
PostUp = firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i ${SERVER_AWG_NIC} -o ${SERVER_PUB_NIC} -j ACCEPT
PostDown = firewall-cmd --direct --remove-rule ipv6 filter FORWARD 0 -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT" >>"${SERVER_AWG_CONF}"
        fi

        echo "PostDown = firewall-cmd --zone=public --remove-port=${SERVER_PORT}/udp
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_AWG_NIC}" >>"${SERVER_AWG_CONF}"
    elif [[ ${USE_NFTABLES} == 'y' ]]; then
        NFTABLES_SCRIPT_PATH="${AMNEZIAWG_DIR}/nft.sh"
        cat << 'EOF' > "${NFTABLES_SCRIPT_PATH}"
#!/bin/bash
ACTION="$1"
PORT="$2"
PUB_NIC="$3"
AWG_NIC="$4"
TABLE_NAME="awg_${AWG_NIC}"

if [[ "${ACTION}" == 'up' ]]; then
    # Create self-contained table for AmneziaWG
    nft delete table inet "${TABLE_NAME}" 2>/dev/null || true
    nft add table inet "${TABLE_NAME}"
    nft add chain inet "${TABLE_NAME}" input "{ type filter hook input priority filter; policy accept; }"
    nft add rule inet "${TABLE_NAME}" input udp dport "${PORT}" accept
    nft add chain inet "${TABLE_NAME}" forward "{ type filter hook forward priority filter; policy accept; }"
    nft add rule inet "${TABLE_NAME}" forward iifname "${AWG_NIC}" accept
    nft add rule inet "${TABLE_NAME}" forward iifname "${PUB_NIC}" oifname "${AWG_NIC}" accept
    nft add chain inet "${TABLE_NAME}" postrouting "{ type nat hook postrouting priority srcnat; policy accept; }"
    nft add rule inet "${TABLE_NAME}" postrouting oifname "${PUB_NIC}" masquerade

    # Also allow in inet filter if an existing firewall table is present
    if nft list table inet filter >/dev/null 2>&1; then
        if nft list chain inet filter input >/dev/null 2>&1; then
            nft add rule inet filter input udp dport "${PORT}" comment "${TABLE_NAME}" accept
        fi
        if nft list chain inet filter forward >/dev/null 2>&1; then
            nft add rule inet filter forward iifname "${AWG_NIC}" comment "${TABLE_NAME}" accept
            nft add rule inet filter forward iifname "${PUB_NIC}" oifname "${AWG_NIC}" comment "${TABLE_NAME}" accept
        fi
    fi
elif [[ "${ACTION}" == 'down' ]]; then
    # Remove rules from inet filter if present
    if nft list table inet filter >/dev/null 2>&1; then
        for chain in input forward; do
            if nft list chain inet filter "${chain}" >/dev/null 2>&1; then
                nft -a list chain inet filter "${chain}" | grep -E 'comment "'${TABLE_NAME}'"' | awk '{print $NF}' | while read -r handle; do
                    nft delete rule inet filter "${chain}" handle "${handle}" 2>/dev/null || true
                done
            fi
        done
    fi

    # Atomically delete dedicated table
    nft delete table inet "${TABLE_NAME}" 2>/dev/null || true
fi
EOF
        chmod +x "${NFTABLES_SCRIPT_PATH}"
        echo "PostUp = ${NFTABLES_SCRIPT_PATH} up ${SERVER_PORT} ${SERVER_PUB_NIC} ${SERVER_AWG_NIC}
PreDown = ${NFTABLES_SCRIPT_PATH} down ${SERVER_PORT} ${SERVER_PUB_NIC} ${SERVER_AWG_NIC}" >>"${SERVER_AWG_CONF}"
    else
        echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >> "${SERVER_AWG_CONF}"

        if [[ "$USE_IPV6" = 'y' ]]; then
            echo "PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >> "${SERVER_AWG_CONF}"  
        fi
    fi

    # Enable routing on the server
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/awg.conf

    if [[ "$USE_IPV6" = 'y' ]]; then
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/awg.conf
    fi

    sysctl --system

    systemctl start "awg-quick@${SERVER_AWG_NIC}"
    systemctl enable "awg-quick@${SERVER_AWG_NIC}"

    newClient
    echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

    # Check if AmneziaWG is running
    systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
    AWG_RUNNING=$?

    # AmneziaWG might not work if we updated the kernel. Tell the user to reboot
    if [[ ${AWG_RUNNING} -ne 0 ]]; then
        echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
        echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
        echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_AWG_NIC}\", please reboot!${NC}"
    else # AmneziaWG is running
        echo -e "\n${GREEN}AmneziaWG is running.${NC}"
        echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_AWG_NIC}\n\n${NC}"
        echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
    fi
}

function newClient() {
    CLIENT_NAME=""
    CLIENT_EXISTS=""
    IPV4_EXISTS=""
    IPV6_EXISTS=""
    DOT_IP=""
    CLIENT_DOT_IP=""
    CLIENT_DOT_IP6=""

    # If SERVER_PUB_IP is IPv6, add brackets if missing
    if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
        if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
            SERVER_PUB_IP="[${SERVER_PUB_IP}]"
        fi
    fi
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

    echo ""
    echo "Client configuration"
    echo ""
    echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
        read -rp "Client name: " -e CLIENT_NAME
        CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "${SERVER_AWG_CONF}")

        if [[ ${CLIENT_EXISTS} != 0 ]]; then
            echo ""
            echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
            echo ""
        fi
    done

    IPV4_NET=$(echo "$SERVER_AWG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
    SERVER_LAST_OCTET=$(echo "$SERVER_AWG_IPV4" | awk -F '.' '{ print $4 }')
    DOT_IP=""
    for i in {2..254}; do
        if [[ "$i" == "$SERVER_LAST_OCTET" ]]; then
            continue
        fi
        DOT_EXISTS=$(grep -c -F "${IPV4_NET}.${i}/" "${SERVER_AWG_CONF}")
        if [[ ${DOT_EXISTS} == '0' ]]; then
            DOT_IP="$i"
            break
        fi
    done

    if [[ -z "${DOT_IP}" ]]; then
        echo ""
        echo "The subnet configured supports only 253 clients."
        exit 1
    fi

    BASE_IP="${IPV4_NET}"
    until [[ ${IPV4_EXISTS} == '0' ]]; do
        read -rp "Client AmneziaWG IPv4: ${BASE_IP}." -e -i "${DOT_IP}" CLIENT_DOT_IP
        CLIENT_DOT_IP="${CLIENT_DOT_IP:-${DOT_IP}}"
        CLIENT_AWG_IPV4="${BASE_IP}.${CLIENT_DOT_IP}"
        IPV4_EXISTS=$(grep -c -F "$CLIENT_AWG_IPV4/32" "${SERVER_AWG_CONF}")

        if [[ ${IPV4_EXISTS} != 0 ]]; then
            echo ""
            echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
            echo ""
        fi
    done

    if [[ ${USE_IPV6} == 'y' ]]; then
        BASE_IP=$(echo "$SERVER_AWG_IPV6" | awk -F '::' '{ print $1 }')
        until [[ ${IPV6_EXISTS} == '0' ]]; do
            read -rp "Client AmneziaWG IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" CLIENT_DOT_IP6
            CLIENT_DOT_IP6="${CLIENT_DOT_IP6:-${DOT_IP}}"
            CLIENT_AWG_IPV6="${BASE_IP}::${CLIENT_DOT_IP6}"
            IPV6_EXISTS=$(grep -c -F "${CLIENT_AWG_IPV6}/128" "${SERVER_AWG_CONF}")

            if [[ ${IPV6_EXISTS} != 0 ]]; then
                echo ""
                echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
                echo ""
            fi
        done
    fi

    # Generate key pair for the client
    CLIENT_PRIV_KEY=$(awg genkey)
    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
    CLIENT_PRE_SHARED_KEY=$(awg genpsk)

    CONFIG_DIR=$(getDirForClientConfig "${CLIENT_NAME}")
    CLIENT_CONFIG="${CONFIG_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

    # Create client file and add the server as a peer
    CLIENT_CONFIG_DNS="${CLIENT_IPV4_DNS_1}, ${CLIENT_IPV4_DNS_2}"
    if [[ "$USE_IPV6" = 'y' ]]; then
        CLIENT_CONFIG_DNS="${CLIENT_CONFIG_DNS}, ${CLIENT_IPV6_DNS_1}, ${CLIENT_IPV6_DNS_2}"
    fi

    CLIENT_ADDRESS="${CLIENT_AWG_IPV4}/32"
    if [[ "$USE_IPV6" = 'y' ]]; then
        CLIENT_ADDRESS="${CLIENT_ADDRESS}, ${CLIENT_AWG_IPV6}/128"
    fi

    echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${CLIENT_CONFIG_DNS}
MTU = ${SERVER_AWG_MTU}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}" > "${CLIENT_CONFIG}"

    if [[ "${AWG_VERSION}" == "3.1" ]]; then
        echo "S3 = ${SERVER_AWG_S3}
S4 = ${SERVER_AWG_S4}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}
HeaderProtectionKey = ${SERVER_AWG_HPK}
ContentPaddingAddition = ${SERVER_AWG_CPA}" >> "${CLIENT_CONFIG}"
    else
        echo "H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}" >> "${CLIENT_CONFIG}"
    fi

    # Append parameters only if they differ from configuration defaults
    if [[ "${SERVER_AWG_RANDOM_TRAILERS}" == "y" ]]; then
        echo "RandomTrailers = on" >> "${CLIENT_CONFIG}"
    fi

    if [[ "${SERVER_AWG_DISABLE_COOKIES}" == "y" ]]; then
        echo "DisableCookies = on" >> "${CLIENT_CONFIG}"
    fi

    for i in 1 2 3 4 5; do
        var="SERVER_AWG_I${i}"
        val="${!var}"
        if [[ -n "${val}" ]]; then
            echo "I${i} = ${val}" >> "${CLIENT_CONFIG}"
        fi
    done

    echo "
[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >> "${CLIENT_CONFIG}"

    if [[ ${KEEPALIVE} -ne 0 ]]; then
        echo "PersistentKeepalive = ${KEEPALIVE}" >>"${CLIENT_CONFIG}"
    fi

    # Add the client as a peer to the server
    echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_ADDRESS}" >> "${SERVER_AWG_CONF}"

    if ip link show dev "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
        awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
    fi

    # Generate QR code if qrencode is installed
    if command -v qrencode &>/dev/null; then
        echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
        qrencode -t ansiutf8 -l L <"${CLIENT_CONFIG}"
        echo ""
    fi

    echo -e "${GREEN}Your client config file is in ${CLIENT_CONFIG}${NC}"
}

function listClients() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
    if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    CLIENT_NUMBER=""
    CLIENT_NAME=""

    echo ""
    echo "Select the existing client you want to revoke"
    grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done

    # match the selected number to a client name
    CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

    # Safely remove [Peer] block matching CLIENT_NAME
    awk -v client="### Client ${CLIENT_NAME}" '
        $0 == client { skip = 1; next }
        skip && /^### Client / { skip = 0 }
        !skip { print }
    ' "${SERVER_AWG_CONF}" > "${SERVER_AWG_CONF}.tmp" && mv "${SERVER_AWG_CONF}.tmp" "${SERVER_AWG_CONF}"

    # remove generated client file
    CONFIG_DIR=$(getDirForClientConfig "${CLIENT_NAME}")
    CLIENT_CONFIG="${CONFIG_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"
    rm -f "${CLIENT_CONFIG}"

    # restart AmneziaWG to apply changes
    if ip link show dev "${SERVER_AWG_NIC}" >/dev/null 2>&1; then
        awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
    fi
}

function showClientQR() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
    if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    CLIENT_NUMBER=""
    CLIENT_NAME=""

    echo ""
    echo "Select the client to show QR code"
    grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done

    # match the selected number to a client name
    CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

    # Get the home directory for the client
    CONFIG_DIR=$(getDirForClientConfig "${CLIENT_NAME}")
    CLIENT_CONFIG="${CONFIG_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

    # Check if the client config file exists
    if [[ -f "${CLIENT_CONFIG}" ]]; then
        echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
        qrencode -t ansiutf8 -l L <"${CLIENT_CONFIG}"
        echo ""
    else
        echo -e "${RED}Client config file not found!${NC}"
    fi
}

function uninstallAmneziaWG() {
    echo ""
    echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
    echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
    read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
    REMOVE=${REMOVE:-n}
    if [[ $REMOVE == 'y' ]]; then
        checkOS

        systemctl stop "awg-quick@${SERVER_AWG_NIC}"
        systemctl disable "awg-quick@${SERVER_AWG_NIC}"

        # Disable routing
        rm -f /etc/sysctl.d/awg.conf
        sysctl --system

        # Remove config files
        rm -rf ${AMNEZIAWG_DIR}/*

        if [[ ${USE_NFTABLES} == 'y' ]]; then NF_PACKAGE="nftables"; else NF_PACKAGE="iptables"; fi

        if [[ ${OS} == 'ubuntu' ]]; then
            apt-get remove -y amneziawg amneziawg-tools
            add-apt-repository -ry ppa:amnezia/ppa
            rm -f /etc/apt/sources.list.d/amneziawg.sources /etc/apt/sources.list.d/amneziawg.sources.list
            apt-get update
        elif [[ ${OS} == 'debian' ]]; then
            apt-get remove -y amneziawg amneziawg-tools
            rm -f /etc/apt/sources.list.d/amneziawg.sources /etc/apt/sources.list.d/amneziawg.sources.list
            rm -f /etc/apt/keyrings/amneziawg-keyring.gpg
            apt-get update
        elif [[ ${OS} == 'fedora' ]]; then
            dnf remove -y amneziawg-kmod amneziawg-tools
            dnf copr disable -y tigro/amneziawg || true
        elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]] || [[ ${OS} == 'rhel' ]]; then
            dnf remove -y kmod-amneziawg amneziawg-dkms amneziawg-tools
            dnf copr disable -y tigro/amneziawg || true
        fi

        # Check if AmneziaWG is running
        systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
        AWG_RUNNING=$?

        if [[ ${AWG_RUNNING} -eq 0 ]]; then
            echo "AmneziaWG failed to uninstall properly."
            exit 1
        else
            echo "AmneziaWG uninstalled successfully."
            echo "You can remove the qrencode and ${NF_PACKAGE} packages yourself if you don't need them."
            exit 0
        fi
    else
        echo ""
        echo "Removal aborted!"
    fi
}

function loadParams() {
    source "${AMNEZIAWG_DIR}/params"
    SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
    AWG_VERSION="${AWG_VERSION:-1.0}"
    SERVER_AWG_MTU="${SERVER_AWG_MTU:-1420}"
    SERVER_AWG_HPK="${SERVER_AWG_HPK:-}"
    SERVER_AWG_CPA="${SERVER_AWG_CPA:-}"
    SERVER_AWG_S3="${SERVER_AWG_S3:-}"
    SERVER_AWG_S4="${SERVER_AWG_S4:-}"
    SERVER_AWG_RANDOM_TRAILERS="${SERVER_AWG_RANDOM_TRAILERS:-n}"
    SERVER_AWG_DISABLE_COOKIES="${SERVER_AWG_DISABLE_COOKIES:-n}"
    SERVER_AWG_I1="${SERVER_AWG_I1:-}"
    SERVER_AWG_I2="${SERVER_AWG_I2:-}"
    SERVER_AWG_I3="${SERVER_AWG_I3:-}"
    SERVER_AWG_I4="${SERVER_AWG_I4:-}"
    SERVER_AWG_I5="${SERVER_AWG_I5:-}"
}

function changeParameters() {
    echo ""
    echo "Change parameters feature is not implemented yet."
}

function backupSettings() {
    echo ""
    echo "--- Backup AmneziaWG settings ---"

    if [[ ! -f "${SERVER_AWG_CONF}" ]]; then
        echo -e "${RED}Error: Server configuration file not found (${SERVER_AWG_CONF})!${NC}"
        return 1
    fi

    local backup_file="$(pwd)/amneziawg-backup.tar.gz"

    local backup_temp
    backup_temp=$(mktemp -d)
    if [[ ! -d "${backup_temp}" ]]; then
        echo -e "${RED}Error: Failed to create temporary directory for backup.${NC}"
        return 1
    fi

    # 1. Copy params
    cp -f "${AMNEZIAWG_DIR}/params" "${backup_temp}/params"

    # 2. Copy server config
    cp -f "${SERVER_AWG_CONF}" "${backup_temp}/${SERVER_AWG_NIC}.conf"

    # 3. Copy nft.sh if nftables is used or file exists
    if [[ -f "${AMNEZIAWG_DIR}/nft.sh" ]]; then
        cp -f "${AMNEZIAWG_DIR}/nft.sh" "${backup_temp}/nft.sh"
    fi

    # 4. Find and copy client config files (only those registered in server config)
    mkdir -p "${backup_temp}/clients"

    local client_names
    client_names=$(grep -E "^### Client " "${SERVER_AWG_CONF}" | awk '{print $3}')
    for client in ${client_names}; do
        local cfg_file="${SERVER_AWG_NIC}-client-${client}.conf"
        local expected_dir
        expected_dir=$(getDirForClientConfig "${client}")
        if [[ -f "${expected_dir}/${cfg_file}" ]]; then
            cp -f "${expected_dir}/${cfg_file}" "${backup_temp}/clients/"
        elif [[ -f "${AMNEZIAWG_DIR}/${cfg_file}" ]]; then
            cp -f "${AMNEZIAWG_DIR}/${cfg_file}" "${backup_temp}/clients/"
        elif [[ -f "/root/${cfg_file}" ]]; then
            cp -f "/root/${cfg_file}" "${backup_temp}/clients/"
        elif [[ -f "$(pwd)/${cfg_file}" ]]; then
            cp -f "$(pwd)/${cfg_file}" "${backup_temp}/clients/"
        else
            for hdir in /home/*; do
                if [[ -d "${hdir}" && -f "${hdir}/${cfg_file}" ]]; then
                    cp -f "${hdir}/${cfg_file}" "${backup_temp}/clients/"
                    break
                fi
            done
        fi
    done

    local client_count
    client_count=$(find "${backup_temp}/clients" -type f -name "*.conf" 2>/dev/null | wc -l)

    # 5. Create archive
    if tar -czf "${backup_file}" -C "${backup_temp}" .; then
        chmod 600 "${backup_file}"
        if [[ -n "${SUDO_USER}" && "${SUDO_USER}" != "root" ]]; then
            chown "${SUDO_USER}:${SUDO_USER}" "${backup_file}" 2>/dev/null || true
        fi
        echo ""
        echo -e "${GREEN}Backup created successfully!${NC}"
        echo "Archive: ${backup_file}"
        echo "Archive contents:"
        echo "  - params"
        echo "  - ${SERVER_AWG_NIC}.conf"
        [[ -f "${backup_temp}/nft.sh" ]] && echo "  - nft.sh"
        echo "  - Client configs: ${client_count} found and backed up"
    else
        echo -e "${RED}Error: Failed to create archive.${NC}"
        rm -rf "${backup_temp}"
        return 1
    fi

    rm -rf "${backup_temp}"
}

function restoreSettings() {
    echo ""
    echo "--- Restore AmneziaWG settings ---"

    local backup_file="$(pwd)/amneziawg-backup.tar.gz"

    if [[ ! -f "${backup_file}" ]]; then
        echo -e "${RED}Backup archive not found: ${backup_file}${NC}"
        echo "Please make sure 'amneziawg-backup.tar.gz' is located in the current directory ($(pwd))."
        return 1
    fi

    echo "Found backup archive: ${backup_file}"

    # Verify tar.gz archive
    if ! tar -tzf "${backup_file}" >/dev/null 2>&1; then
        echo -e "${RED}Error: The file is not a valid .tar.gz archive.${NC}"
        return 1
    fi

    local restore_temp
    restore_temp=$(mktemp -d)
    if [[ ! -d "${restore_temp}" ]]; then
        echo -e "${RED}Error: Failed to create temporary directory for extraction.${NC}"
        return 1
    fi

    if ! tar -xzf "${backup_file}" -C "${restore_temp}"; then
        echo -e "${RED}Error: Failed to extract archive.${NC}"
        rm -rf "${restore_temp}"
        return 1
    fi

    if [[ ! -f "${restore_temp}/params" ]]; then
        echo -e "${RED}Error: Archive does not contain 'params' file! Restore aborted.${NC}"
        rm -rf "${restore_temp}"
        return 1
    fi

    local restored_nic
    restored_nic=$(grep -E '^SERVER_AWG_NIC=' "${restore_temp}/params" | cut -d '=' -f 2 | tr -d '"'\'' ')
    restored_nic="${restored_nic:-awg0}"

    if [[ ! -f "${restore_temp}/${restored_nic}.conf" ]]; then
        local found_conf
        found_conf=$(find "${restore_temp}" -maxdepth 1 -name "*.conf" ! -name "*-client-*" | head -n 1)
        if [[ -n "${found_conf}" ]]; then
            cp -f "${found_conf}" "${restore_temp}/${restored_nic}.conf"
        else
            echo -e "${RED}Error: Archive does not contain server config (${restored_nic}.conf)! Restore aborted.${NC}"
            rm -rf "${restore_temp}"
            return 1
        fi
    fi

    local restored_store_client
    restored_store_client=$(grep -E '^STORE_CLIENT=' "${restore_temp}/params" | cut -d '=' -f 2 | tr -d '"'\'' ')
    restored_store_client="${restored_store_client:-y}"

    echo ""
    echo -e "${ORANGE}WARNING: Restoring will overwrite current AmneziaWG configuration and client settings.${NC}"
    echo "Restoring server interface: ${restored_nic}"
    echo "Client storage mode (STORE_CLIENT): ${restored_store_client}"
    local confirm_restore=""
    read -rp "Are you sure you want to proceed? [y/n]: " -e confirm_restore
    if [[ "${confirm_restore,,}" != "y" ]]; then
        echo "Restore cancelled."
        rm -rf "${restore_temp}"
        return 0
    fi

    # Stop active service
    if [[ -n "${SERVER_AWG_NIC}" ]] && systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}" 2>/dev/null; then
        systemctl stop "awg-quick@${SERVER_AWG_NIC}" 2>/dev/null || true
    fi
    if [[ "${restored_nic}" != "${SERVER_AWG_NIC}" ]] && systemctl is-active --quiet "awg-quick@${restored_nic}" 2>/dev/null; then
        systemctl stop "awg-quick@${restored_nic}" 2>/dev/null || true
    fi

    # Ensure AMNEZIAWG_DIR exists
    mkdir -p "${AMNEZIAWG_DIR}"
    chmod 700 "${AMNEZIAWG_DIR}"

    # 1. Restore params
    cp -f "${restore_temp}/params" "${AMNEZIAWG_DIR}/params"
    chmod 600 "${AMNEZIAWG_DIR}/params"
    echo "  - Restored params to ${AMNEZIAWG_DIR}/params"

    # 2. Restore server config
    cp -f "${restore_temp}/${restored_nic}.conf" "${AMNEZIAWG_DIR}/${restored_nic}.conf"
    chmod 600 "${AMNEZIAWG_DIR}/${restored_nic}.conf"
    echo "  - Restored server config to ${AMNEZIAWG_DIR}/${restored_nic}.conf"

    # 3. Restore nft.sh if present
    if [[ -f "${restore_temp}/nft.sh" ]]; then
        cp -f "${restore_temp}/nft.sh" "${AMNEZIAWG_DIR}/nft.sh"
        chmod 755 "${AMNEZIAWG_DIR}/nft.sh"
        echo "  - Restored nftables script to ${AMNEZIAWG_DIR}/nft.sh"
    fi

    # 4. Restore client configs with respect to STORE_CLIENT from backup
    local client_count=0
    while IFS= read -r -d '' client_file; do
        local client_file_base
        client_file_base=$(basename "${client_file}")
        local cname=""
        if [[ "${client_file_base}" =~ ^.*-client-(.+)\.conf$ ]]; then
            cname="${BASH_REMATCH[1]}"
        fi

        local target_dir
        if [[ "${restored_store_client}" == 'y' ]]; then
            target_dir="${AMNEZIAWG_DIR}"
        else
            target_dir=$(getHomeDirForClient "${cname}")
        fi

        mkdir -p "${target_dir}"
        cp -f "${client_file}" "${target_dir}/${client_file_base}"
        chmod 600 "${target_dir}/${client_file_base}"
        if [[ -n "${SUDO_USER}" && "${SUDO_USER}" != "root" && "${target_dir}" == /home/* ]]; then
            chown "${SUDO_USER}:${SUDO_USER}" "${target_dir}/${client_file_base}" 2>/dev/null || true
        fi
        echo "  - Restored client config: ${client_file_base} -> ${target_dir}/"
        client_count=$((client_count + 1))
    done < <(find "${restore_temp}" -type f -name "*-client-*.conf" -print0)

    rm -rf "${restore_temp}"

    # Reload variables from restored params
    loadParams

    # Restart AmneziaWG service
    echo ""
    echo "Restarting AmneziaWG service..."
    systemctl daemon-reload
    systemctl restart "awg-quick@${SERVER_AWG_NIC}" 2>/dev/null || true
    if systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
        echo -e "${GREEN}AmneziaWG (${SERVER_AWG_NIC}) is active and running!${NC}"
    else
        echo -e "${ORANGE}Service restart finished. You can verify status with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
    fi

    echo ""
    echo -e "${GREEN}Restore completed successfully!${NC}"
    echo "Total client configs restored: ${client_count}"
}

function manageMenu() {
    echo "AmneziaWG server installer (https://github.com/romikb/amneziawg-install)"
    echo ""
    echo "It looks like AmneziaWG is already installed."
    echo ""
    echo "What do you want to do?"
    echo "   1) Add a new user"
    echo "   2) List all users"
    echo "   3) Revoke existing user"
    echo "   4) Show client QR code"
    echo "   5) Change parameters"
    echo "   6) Uninstall AmneziaWG"
    echo "   7) Backup settings"
    echo "   8) Restore settings"
    echo "   9) Exit"
    until [[ ${MENU_OPTION} =~ ^[1-9]$ ]]; do
        read -rp "Select an option [1-9]: " MENU_OPTION
    done
    case "${MENU_OPTION}" in
    1)
        newClient
        ;;
    2)
        listClients
        ;;
    3)
        revokeClient
        ;;
    4)
        showClientQR
        ;;
    5)
        changeParameters
        ;;
    6)
        uninstallAmneziaWG
        ;;
    7)
        backupSettings
        ;;
    8)
        restoreSettings
        ;;
    9)
        exit 0
        ;;
    esac
}

# Check for root, virt, OS...
initialCheck

# Check if AmneziaWG is already installed and load params
if [[ -e "${AMNEZIAWG_DIR}/params" ]]; then
    loadParams
    manageMenu
else
    installAmneziaWG
fi
