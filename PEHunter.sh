#!/bin/bash

# Renk kodları
GREEN="\033[92m"
RED="\033[91m"
BLUE="\033[94m"
YELLOW="\033[93m"
RESET="\033[0m"

# Banner
echo -e "${RED}"
echo "=================================================="
echo "   ██████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ "
echo "   ██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
echo "   ██████╔╝█████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
echo "   ██╔═══╝ ██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
echo "   ██║     ███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
echo "   ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
echo "--------------------------------------------------"
echo "              🔎  PEHunter v1.0 🔎"
echo "   Linux Privilege Escalation Scanner Tool"
echo "=================================================="
echo -e "${RESET}"


# Çıktı dosyası
OUTPUT_FILE="linpeas_output_$(date +%Y%m%d_%H%M%S).txt"

# Sistem versiyonunu al
get_system_version() {
    echo -e "${YELLOW}[*] Sistem bilgisi alınıyor...${RESET}"
    KERNEL_VERSION=$(uname -r)
    OS_VERSION=$(lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
    echo -e "${GREEN}[+] Kernel Version: $KERNEL_VERSION${RESET}"
    echo -e "${GREEN}[+] OS Version: $OS_VERSION${RESET}"
}

# LinPEAS'i indir ve çalıştır
run_linpeas() {
    echo -e "${YELLOW}[*] LinPEAS kontrol ediliyor...${RESET}"
    
    if [ -f "./linpeas.sh" ]; then
        echo -e "${GREEN}[+] linpeas.sh bulundu!${RESET}"
    else
        echo -e "${YELLOW}[!] linpeas.sh bulunamadı. İndiriliyor...${RESET}"
        if command -v wget >/dev/null 2>&1; then
            wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
        elif command -v curl >/dev/null 2>&1; then
            curl -s -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
        else
            echo -e "${RED}[-] wget veya curl bulunamadı!${RESET}"
            exit 1
        fi
        
        if [ ! -f "./linpeas.sh" ]; then
            echo -e "${RED}[-] linpeas.sh indirilemedi!${RESET}"
            exit 1
        fi
    fi
    
    chmod +x linpeas.sh
    echo -e "${YELLOW}[*] LinPEAS çalıştırılıyor... (Bu işlem birkaç dakika sürebilir)${RESET}"
    echo -e "${BLUE}[*] Çıktı $OUTPUT_FILE dosyasına kaydediliyor...${RESET}"
    
    ./linpeas.sh > "$OUTPUT_FILE" 2>&1
    
    if [ -f "$OUTPUT_FILE" ]; then
        echo -e "${GREEN}[+] LinPEAS çıktısı $OUTPUT_FILE dosyasına kaydedildi.${RESET}"
    else
        echo -e "${RED}[-] LinPEAS çıktısı kaydedilemedi!${RESET}"
        exit 1
    fi
}

# ExploitDB'den CVE ara
search_exploitdb() {
    local search_term="$1"
    echo -e "${YELLOW}[*] ExploitDB'de '$search_term' araniyor...${RESET}"
    
    # ExploitDB arama URL'si
    SEARCH_URL="https://www.exploit-db.com/search?q=${search_term}"
    
    # User-Agent ile istek gönder
    USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    
    # Curl ile arama yap
    RESPONSE=$(curl -s -H "User-Agent: $USER_AGENT" "$SEARCH_URL")
    
    if [ $? -eq 0 ]; then
        # HTML'den exploit linklerini çıkar
        EXPLOITS=$(echo "$RESPONSE" | grep -oP '/exploits/[0-9]+' | sort -u)
        
        if [ -n "$EXPLOITS" ]; then
            echo -e "${GREEN}[+] $search_term için exploit(ler) bulundu:${RESET}"
            echo "$EXPLOITS" | while read -r exploit_path; do
                if [ -n "$exploit_path" ]; then
                    echo -e "${BLUE}  → https://www.exploit-db.com$exploit_path${RESET}"
                fi
            done
            echo ""
        else
            echo -e "${YELLOW}[!] $search_term için exploit bulunamadı.${RESET}"
        fi
    else
        echo -e "${RED}[-] ExploitDB'ye bağlanılamadı!${RESET}"
    fi
}

# CVE ve güvenlik açığı taraması
analyze_output() {
    if [ ! -f "$OUTPUT_FILE" ]; then
        echo -e "${RED}[-] Analiz edilecek dosya bulunamadı!${RESET}"
        return
    fi
    
    echo -e "${YELLOW}[*] LinPEAS çıktısı analiz ediliyor...${RESET}"
    
    # Kernel versiyonu için exploit ara
    if [ -n "$KERNEL_VERSION" ]; then
        search_exploitdb "$KERNEL_VERSION"
        
        # Kernel major version için de ara
        KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f1-2)
        search_exploitdb "linux kernel $KERNEL_MAJOR"
    fi
    
    # SUID dosyaları kontrol et
    echo -e "${YELLOW}[*] SUID dosyaları kontrol ediliyor...${RESET}"
    SUID_FILES=$(grep -i "SUID" "$OUTPUT_FILE" | head -5)
    if [ -n "$SUID_FILES" ]; then
        echo -e "${GREEN}[+] SUID dosyaları bulundu, privilege escalation fırsatları olabilir:${RESET}"
        echo -e "${BLUE}$SUID_FILES${RESET}"
        
        # Bilinen SUID exploit'leri için ara
        search_exploitdb "suid privilege escalation"
    fi
    
    # Sudo bilgilerini kontrol et
    echo -e "${YELLOW}[*] Sudo yapılandırması kontrol ediliyor...${RESET}"
    SUDO_INFO=$(grep -i "sudo" "$OUTPUT_FILE" | head -3)
    if [ -n "$SUDO_INFO" ]; then
        echo -e "${GREEN}[+] Sudo bilgileri bulundu:${RESET}"
        echo -e "${BLUE}$SUDO_INFO${RESET}"
        search_exploitdb "sudo privilege escalation"
    fi
    
    # Cron job'ları kontrol et
    echo -e "${YELLOW}[*] Cron job'ları kontrol ediliyor...${RESET}"
    CRON_INFO=$(grep -i "cron" "$OUTPUT_FILE" | head -3)
    if [ -n "$CRON_INFO" ]; then
        echo -e "${GREEN}[+] Cron job bilgileri bulundu:${RESET}"
        echo -e "${BLUE}$CRON_INFO${RESET}"
        search_exploitdb "cron privilege escalation"
    fi
}

# Ana fonksiyon
main() {
    # Sistem bilgilerini al
    get_system_version
    
    echo ""
    
    # LinPEAS'i çalıştır
    run_linpeas
    
    echo ""
    echo -e "${YELLOW}[*] Exploit araması başlatılıyor...${RESET}"
    echo ""
    
    # Çıktıyı analiz et ve exploit ara
    analyze_output
    
    echo ""
    echo -e "${GREEN}[+] Tarama tamamlandı!${RESET}"
    echo -e "${BLUE}[*] Detaylı çıktı: $OUTPUT_FILE${RESET}"
    echo -e "${YELLOW}[!] Bulunan exploit'leri kullanmadan önce sistemi yedekleyin!${RESET}"
}

# Script çalıştırılıyor mu kontrol et
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

