#!/usr/bin/bash

BOLD="\033[01;01m"     
RED="\033[01;31m"      
GREEN="\033[01;32m"    
YELLOW="\033[01;33m"   
RESET="\033[00m" 

check_system_package() {
    if [ -e /usr/bin/$1 ]; then
        echo -e $YELLOW "[ - ] Checking packages"
        sleep 1
        echo -e $GREEN "[ ✔ ] $1 ................[ found ]"
    else 
        echo -e $RED "[ X ] $1 -> Installing"
        sudo apt-get install -y $1
    fi
}

check_system_package "xdotool"

check_python_module() {
    python3 -c "import $1" &> /dev/null
    if [ $? -eq 0 ]; then
        echo -e "$GREEN [ ✔ ] $1 ................[ found ]$RESET"
    else
        echo -e "$RED [ X ] $1 -> Not found! Installing...$RESET"
        read -p "Proceed with installation of $1? (y/n): " choice
        if [[ $choice == [Yy]* ]]; then
            python3 -m pip install $1
            if [ $? -eq 0 ]; then
                echo -e "$GREEN [ ✔ ] $1 ................[ installed successfully ]$RESET"
            else
                echo -e "$RED [ X ] Failed to install $1$RESET"
            fi
        else
            echo -e "$YELLOW [ - ] Skipping installation of $1$RESET"
        fi
    fi
}

modules=("scapy" "time" "platform" "subprocess" "colorama" "rich" "datetime" "itertools" "csv")

for module in "${modules[@]}"
do
    check_python_module $module
done
