#!/bin/bash

###############################################################
# Domain Mapper 
# Author: Michael Pritsert
# GitHub: https://github.com/mishap2001
# LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a
# License: MIT License
###############################################################


function ROOT() # check if the user is root. 
                # If not, suggests to become one or exit.
{
	USER=$(whoami)
	if [ $USER != "root" ]; then
		echo "
Warning! Only root is allowed to run the script.
Would you like to become one?
Yes - become one
No - exit the script
(Y/N)"
		read root_answer
		case $root_answer in
			y|Y)
			sudo -i
			echo "You are now root! You may continue..."
			;;
			
			n|N)
			echo "Exiting script!"
			exit
			;;
		esac	
	else
		echo "Checking user..."
		sleep 2
		echo "You are root! Continuing..."
		sleep 2
		echo
		
	fi	
}	
ROOT

function APPS() # Check if crucial apps are installed, if not install them.
{
	echo "----------------------------------"
	echo "Checking for crucial applications:"
	echo "----------------------------------"
	for app in nmap sshpass whois geoiplookup nipe; do
	#special handling for nipe because of it's location
	if [ $app = nipe ]; then
		if [ -d /home/kali/nipe ]; then
				echo "nipe: installed"
				else
			cd /home/kali
			git clone https://github.com/htrgouvea/nipe && cd nipe
			sudo apt-get install cpanminus -y
			sudo cpanm --installdeps .
			sudo perl nipe.pl install
			echo "nipe installed succesfully"
			fi
	else
	#handling for the other applications
    if command -v "$app" >/dev/null; then
        echo "$app: installed "
    else
        echo "$app: NOT installed, installing now..."
        case "$app" in
			nmap)
			sudo apt-get update && sudo apt-get install -y nmap
			;;
			
			sshpass)
			sudo apt-get update && sudo apt-get install -y sshpass
			;;
			
			whois)
			sudo apt-get update && sudo apt-get install -y whois
			;;
			
			geoiplookup)
			sudo apt-get update && sudo apt-get install -y geoip-bin
			;;
		esac
    fi
    fi
done
echo
}
APPS

function ANON() # Check for anonymity.
				# If not, suggest to become anonymous.
				# If anonymous - continue.
{
	echo "----------------------"
	echo "Cheking for anonymity:"
	echo "----------------------"
	#configuring assignments
	IP=$(curl -s ifconfig.co)
	GPS=$(geoiplookup "$IP" | awk '{print $4, $5, $6}')
	
	if geoiplookup "$IP" | grep -iq israel; then
		echo "You are in: $GPS and not anonymous! Would yo like to become anonymous? (Y/N)" 
		read answer
		case "$answer" in
			y|Y)
			cd /home/kali/nipe
			sudo perl nipe.pl start
			sudo perl nipe.pl restart
			spoof=$(sudo perl nipe.pl status)
			echo "You are anonymous and ready to go!"
			echo "Your spoofing location address and status are: $spoof"
	IP_NIPE=$(curl -s ifconfig.co)
	GPS_NIPE=$(geoiplookup "$IP_NIPE" | awk '{print $4, $5, $6}')		
			echo "$GPS_NIPE" 			
			;;
			
			n|N)
			echo "EXITING..."
			exit
			;;
		esac
	else 
		echo "You are anonymous and ready to go!"
	fi
}
ANON

function TARGET()
{
	#Entry credentials
	echo ""
	echo "------------------------------------"
	echo "Who is the target? enter IP address:"
	echo "------------------------------------" 
	read target_IP
	echo ""
	echo "--------------------------------------------"
	echo "Enter the username of the target SSH server:"
	echo "--------------------------------------------"
	read target_U
	echo ""
	echo "--------------------------------------------"
	echo "Enter the password of the target SSH server:"
	echo "--------------------------------------------"
	read target_P
	echo ""
	echo "-----------------------------------"
	echo "Enter the address you want to scan:"
	echo "-----------------------------------"
	read target_scanwho
	echo ""
	
	# Commands - Display country, IP, uptime. check whois. scan for open ports.
	 
	#IP extraction
	echo "The IP of the target -" >> target_data.txt
	sshpass -p $target_P ssh -o StrictHostKeyChecking=no $target_U@$target_IP "curl -s ifconfig.me" >> target_data.txt
	echo "" >> target_data.txt 
	echo "" >> target_data.txt         
	echo "$(date) - Finished extracting IP address" >> target_log.txt
	
	# Country extraction
	echo "The target originates from -" >> target_data.txt
	IP_T=$(curl -s ifconfig.me)
	sshpass -p $target_P ssh -o StrictHostKeyChecking=no $target_U@$target_IP "curl -s ipinfo.io $IP_T | grep -i country | sed 's/[\",]//g'" >> target_data.txt
	echo "" >> target_data.txt        
	echo "$(date) - Finished extracting target country" >> target_log.txt
	
	# uptime extraction
	echo "The targets uptime is -" >> target_data.txt
	sshpass -p $target_P ssh -o StrictHostKeyChecking=no $target_U@$target_IP "uptime" >> target_data.txt 
	echo "" >> target_data.txt       
	echo "$(date) - Finished extracting target uptime" >> target_log.txt
	
	# whois extraction
	echo " [*] Executing 'whois $target_scanwho'"
	echo ""
	echo "whois for $target_scanwho" >> target_whois.txt
	sshpass -p $target_P ssh -o StrictHostKeyChecking=no $target_U@$target_IP "whois $target_scanwho" >> target_whois.txt       
	echo "$(date) - Finished extracting whois for $target_scanwho to 'target_whois.txt'" >> target_log.txt
	
	# Open ports extraction
	echo " [*] Searching for open ports on $target_scanwho using 'nmap'"
	echo ""
	echo "nmap for $target_scanwho" >> target_nmap.txt
	sshpass -p $target_P ssh -o StrictHostKeyChecking=no $target_U@$target_IP "nmap --open $target_scanwho" >> target_nmap.txt        
	echo "$(date) - Finished extracting nmap for $target_scanwho to 'target_nmap.txt'" >> target_log.txt
	echo ""
	echo "Finished!"
	sleep 2
	echo ""
	echo "-------------------------------------------------------------------------------------------"
	echo "The data is saved in: target_data.txt, target_whois.txt, target_nmap.txt and target_log.txt"
	echo "-------------------------------------------------------------------------------------------"
}
TARGET










