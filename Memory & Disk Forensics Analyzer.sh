#!/bin/bash

###############################################################
# Memory & Disk Forensics Analyzer Script
# Author: Michael Pritsert
# GitHub: https://github.com/mishap2001
# LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a
# License: MIT License
###############################################################


function ROOT() # check if the user is root. If not, suggests to re-run as root or exit. 
{
	USER=$(whoami)
	if [ $USER != "root" ]; then

	echo "Warning! Only root is allowed to run the script."
	echo "You can either run the script with sudo or become root."
	echo "Would you like to become one?"
	echo "Yes - become one and run the script again"
	echo "No - exit the script"
	echo "(Y/N)"
		read root_answer
		case $root_answer in
			y|Y)
			echo "Re-running script as root..."
			sudo  bash "$0" "$@"
			exit # exit the script that runs without root to prevent loop
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
		echo ""
		
	fi	
}
	
function APPS() # Check if forensic tools are installed, if not - install them.
{
	echo "----------------------------"
	echo "Checking for forensic tools:"
	echo "----------------------------"
	for app in binwalk foremost strings bulk_extractor zip ; do
		if command -v "$app" >/dev/null; then
			echo "$app: installed "
		else
			echo "$app: NOT installed, installing now..."
			case "$app" in
				binwalk)
				sudo apt-get update && sudo apt-get install -y binwalk
				;;
			
				foremost)
				sudo apt-get update && sudo apt-get install -y foremost
				;;
			
				strings)
				sudo apt-get update && sudo apt-get install -y binutils
				;;
			
				bulk_extractor)
				sudo apt-get update && sudo apt-get install -y bulk-extractor
				;;
				
				zip)
				sudo apt-get update && sudo apt-get install -y zip
				;;
			esac	
		fi
	done	
	# volatility needs special handling
		# volatility 2.6
		if [ -f vol2 ]; then
			echo "volatility2: installed"
		else
			echo "volatility not found - installing now"
			wget https://github.com/volatilityfoundation/volatility/releases/download/2.6.1/volatility_2.6_lin64_standalone.zip
			unzip volatility_2.6_lin64_standalone.zip
			cd volatility_2.6_lin64_standalone
			mv volatility_2.6_lin64_standalone vol2
			mv vol ..
			cd ..
			rm -r volatility_2.6_lin64_standalone.zip
			rm -r volatility_2.6_lin64_standalone
			echo ""
			echo "volatility 2.6 is installed and saved under the name 'vol2'"
		fi
		# volatility 3
		if  vol -h >/dev/null 2>&1 ; then
			echo "volatility3: installed"
		else
			sudo apt update
			sudo apt install python3 python3-pip -y 	# just in case
			sudo pip3 install volatility3 --break-system-packages
			echo "Volatility 3 is installed"
		fi	
echo ""
}

function CHOICE() # Choose what to scan - a file or a directory and execute accordingly
{
	# The user needs to specify the file name. If it exists - the script 
	# proceeds, if not, the user gets one more chance to get it right.
	# There is also an option for a full directory.
	echo "-----------------------------"
	echo "What do you want to analyze? "
	echo "1. Single File"
	echo "2. All files in a directory"
	echo "-----------------------------"
	read MODE
	echo
	case "$MODE" in
		1)
		echo "------------------------------------"
		echo "What file would you like to analyze?"
		echo "------------------------------------"
		read FILE 
		echo
		if [ -f $FILE ]; then
			sleep 1
			echo "------------------------------"
			echo "The file exists, proceeding..."
			echo "------------------------------"
			echo
			SCAN_TOOL "$FILE"
		else
			sleep 1
			echo "-------------------------------------------"
			echo "The file does not exist, type again or exit"
			echo "What would you like to do?"
			echo "-------------------------------------------"
			echo "1. Type again"
			echo "2. Exit"
			echo "-------------"
	    read INSTR
				case $INSTR in
					1)
					echo "---------------"
					echo "Type file name:"
					echo "---------------"
					read FILE2
					if [ -f $FILE2 ]; then
						sleep 1
						echo
						echo "------------------------------"
						echo "The file exists, proceeding..."
						echo "------------------------------"
						FILE="$FILE2"
						echo
						SCAN_TOOL "$FILE"
					else 
						echo "------------------------------------------------------"
						echo "The file does not exist. Check yourself and come back."
						echo "------------------------------------------------------"
						sleep 1
						echo "EXITING..."
						exit
					fi
					;;
					2)
					sleep 1
					echo "Exiting..."
					exit
					;;
				esac
			fi			
			;;
			
			2)
			echo "-------------------"
			echo "Type directory path"
			echo "-------------------"
			read DIR
			echo
			if [ ! -d "$DIR" ]; then
				echo "------------------------------------"
				echo "Directory does not exist. Try again."
				echo "------------------------------------"
				read DIR2
				echo
				if [ -d "$DIR2" ]; then
					sleep 1
					echo
					echo "------------------------------"
					echo "Directory found, proceeding..."
					echo "------------------------------"
					DIR="$DIR2"
					echo					
				else
					echo "-------------------------------------------------------"
					echo "Directory does not exist. Check yourself and come back."
					echo "-------------------------------------------------------"
					sleep 1
					echo "Exiting..."
					exit
				fi
			else
				echo "------------------------------"
				echo "Directory found, proceeding..."
				echo "------------------------------"
				
			fi
			for f in "$DIR"/*; do
				[ -f "$f" ]
				SCAN_TOOL "$f"
			done
			;;
			esac								
}

function SCAN_TOOL() # Choose which tools to use
{
	FILE="$1"
    NAME=$(basename "$FILE")

    echo
    echo "----------------------------------------"
    echo "Now analyzing file: $FILE"
    echo "----------------------------------------"
    echo
	echo "What tools would you like to use?"
	echo "1. Regular Tools (both hdd and memory files)"
	echo "[*] binwalk"
	echo "[*] strings"
	echo "[*] foremost"
	echo "[*] bulk_extractor"
	echo "2. Volatility 2 (for memory files only!)"
	echo "3. Volatility 3 (for memory files from win10 system and higher)"
	read tool_choice
	echo
	case $tool_choice in
		1)
			FILE_PROC "$FILE"
		;;		
		
		2)
			VOLATILITY2_CHECK
		;;
		
		3)
			VOLATILITY3_CHECK
		;;	
	esac	
}

function FILE_PROC() # Execute regular carving tools on chosen file/directory
{
	
 # what is FILE?
	FILE="$1"
	NAME=$(basename "$FILE")
	TIME=$(date)
 # create a parent directory for each scanned file
	PARENTDIR="${NAME}_RESULTS"
	echo "================="
	echo "STARTING ANALYSIS"
	echo "================="
	echo
	mkdir -p "$PARENTDIR"
	echo "------------------------------------------------------"
	echo "Created parent directory named - {$PARENTDIR}"
	echo "------------------------------------------------------"
	echo
		
 # automatic carving with different tools
	
	# binwalk
	# doing binwalk on HDD may take some time because of its size!!!
	echo "[*] Executing 'binwalk' on the file '$NAME'"
	echo
	binwalk "$FILE" > "$PARENTDIR/binwalk.txt"
	echo "[!] Executed 'binwalk' on the file '$NAME'. Results are saved inside '$PARENTDIR/binwalk.txt'"
	echo
	
	# strings - predefined searches with the option
	# of manual search
	sleep 1	
	mkdir -p "$PARENTDIR/strings"
	echo "---------------------------------"
	echo "Created the directory - {strings}"
	echo "---------------------------------"
	echo 
	echo "[*] Executing 'strings' on the file '$NAME'"
	echo
	strings "$FILE" | grep -Ewi "exe" > "$PARENTDIR/strings/strings_exe.txt"
	echo "[1] Extracted exe files to 'strings_exe.txt'"
	echo
	strings "$FILE" | grep -Eio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' > "$PARENTDIR/strings/strings_emails.txt"
	echo "[2] Extracted emails to 'strings_emails.txt'"
	echo	
	strings "$FILE" | grep -Ewi "(username|password)" > "$PARENTDIR/strings/strings_credentials.txt"
	echo "[3] Extracted credentials to 'strings_credentials.txt'"
	echo
	strings "$FILE" | grep -Ewi '[A-Za-z0-9._-]+\.(co|com|net|org|info|io|gov|edu)(\.[A-Za-z]{2,})?' > "$PARENTDIR/strings/strings_domains.txt"
	echo "[4] Extracted domains files to 'strings_domains.txt'"
	echo
	echo "Would you like to search for your own keyword?"
	echo "Y/N"
	read strings_answer
		case $strings_answer in
		y|Y)
		    answer=y
			while [ "$answer" = "y" ] || [ "$answer" = "Y" ]; do
				echo "Type keyword:"
				read key
				echo
				strings "$FILE" | grep -i -- "$key" > "$PARENTDIR/strings/strings_${key}.txt"
				echo "Saved to $PARENTDIR/strings/strings_${key}.txt"
				echo
				echo "Search another keyword? (y/n)"
				read answer
				echo
            done
            echo
            echo "[!] All files are saved inside $PARENTDIR/strings"
            echo
            echo "[*] Continuing..." 
        ;;
            		
		n|N)
			echo "[!] All files are saved inside '$PARENTDIR/strings'"
			echo	
			echo "[*] Continuing..."
			echo
		;;
		esac

	# foremost
	mkdir -p "$PARENTDIR/foremost_output"
	echo "-----------------------------------------"
	echo "Created the directory - {foremost_output}"
	echo "-----------------------------------------"
	echo
	echo "[*] Extracting files from '$NAME' using 'foremost'"
	foremost -i $FILE -o $PARENTDIR/foremost_output >/dev/null 2>&1
	echo
	echo "[!] Extracted files using 'foremost' to '$PARENTDIR/foremost_output"
	echo
	sleep 1
	
	# bulk_extractor
	mkdir -p "$PARENTDIR/bulk_output"
	echo "-------------------------------------"
	echo "Created the directory - {bulk_output}"
	echo "-------------------------------------"
	echo "[*] Extracting files from $NAME using 'bulk_extractor'"
	bulk_extractor $FILE -o $PARENTDIR/bulk_output >/dev/null
	echo
	echo "[!] Extracted files using 'bulk_extractor' to '$PARENTDIR/bulk_output'"
	sleep 1
	echo
	echo "Checking for .pcap file..."
	sleep 1
	echo
	if [ -f $PARENTDIR/bulk_output/packets.pcap ]; then
			echo "File found, the location is inside $PARENTDIR/bulk_output."
		while true; do	
			echo "Do you want to leave it there or move it outside?"
			echo "1. Move it"
			echo "2. Leave it"
			read bulk_answer
			case $bulk_answer in
				1)
					echo
					cd "$PARENTDIR/bulk_output"
					mv packets.pcap ..
					cd ..					
					echo "[!] The file has been moved. It's current location and size are:"
					echo "Location - " | pwd 
					echo "Size - " | ls -lh | grep pcap | awk '{print $5}'
					cd ..
					break
				;;
				
				2)
					echo "[!] It's current location and size are:"
					cd "$PARENTDIR/bulk_output"
					echo "Location - " | pwd 
					echo "Size - " | ls -lh | grep pcap | awk '{print $5}'
					cd ..
					cd ..
					break
				;;
				
				*)
				echo "Choice does not exist. Choose again."
				echo
				;;
			esac
		done
			echo "=================="
			echo "Finished analyzing"
			echo "=================="
			echo
			echo "--------------------"
			echo "Creating a report..."
			echo "--------------------"
			REPORT_ZIP "$FILE" "$PARENTDIR" "$TIME"
		else
			echo "The file was not found"
			echo
			echo "------------------"
			echo "Finished analyzing"
			echo "------------------"
			echo
			echo "--------------------"
			echo "Creating a report..."
			echo "--------------------"
			REPORT_ZIP "$FILE" "$PARENTDIR" "$TIME"			
	fi
}

function VOLATILITY2_CHECK() # If vol2 was chosen - check if the file is compatible with volatility 2
{
	sleep 1
	echo "-----------------------------"
	echo "Checking for compatibility..."
	echo "-----------------------------"
	echo	
	# check compatibility for volatility 2 / volatility 3
	# volatility 2
	if [ -z "$(./vol2 -f "$FILE" imageinfo 2>/dev/null | grep 'Suggested Profile' | grep 'No suggestion')" ]
		then
			echo "------------------------------------------"
			echo "The file can be analyzed with volatility 2"
			echo "------------------------------------------"
			sleep 0.5
			echo 	
			VOL2_ANA #if it is compatible - start analyzing
		return
	fi	
		
		echo
		echo "[!]This is not a supported file[!]"
		return
					
}

function VOL2_ANA() # Execute volatility 2 with flags
{
	NAME=$(basename "$FILE")
	RESULTDIR="${NAME}_vol2_RESULT"
	TIME=$(date)
	
	echo "================="
	echo "STARTING ANALYSIS"
	echo "================="	
	echo
	echo "------------------------------------------------------------"
	echo "Running volatility and saving inside - ${RESULTDIR}"
	echo "------------------------------------------------------------"
	echo
	mkdir "${NAME}_vol2_RESULT"
	
	# getting the profile of the memory image
	PROF=$(./vol2 -f "$FILE" imageinfo 2>/dev/null | grep Suggested | awk '{print $4}' | sed 's/,//g')
	echo "[!] The profile of the memory image is - $PROF"
	
	# processes
	echo "[*] Searching for processes"
	mkdir -p "${RESULTDIR}/processes"
	./vol2 -f "$FILE" --profile=$PROF pslist 2>/dev/null > "${RESULTDIR}/processes/pslist.txt" # show active processes
	./vol2 -f "$FILE" --profile=$PROF psscan 2>/dev/null > "${RESULTDIR}/processes/psscan.txt" # show hidden/terminated processes
	./vol2 -f "$FILE" --profile=$PROF pstree 2>/dev/null > "${RESULTDIR}/processes/pstree.txt" # show process hierarchy
	
	# network
	echo "[*] Searching for network"
	mkdir -p "${RESULTDIR}/network"
	./vol2 -f "$FILE" --profile=$PROF netscan 2>/dev/null > "${RESULTDIR}/network/netscan.txt"   # works for win 7 and higher
	./vol2 -f "$FILE" --profile=$PROF connscan 2>/dev/null > "${RESULTDIR}/network/connscan.txt" # works for older versions
	./vol2 -f "$FILE" --profile=$PROF sockscan 2>/dev/null > "${RESULTDIR}/network/sockscan.txt" # detect TCP/UDP
	./vol2 -f "$FILE" --profile=$PROF sockets 2>/dev/null > "${RESULTDIR}/network/sockets.txt"  # detect known sockets
	./vol2 -f "$FILE" --profile=$PROF connections 2>/dev/null > "${RESULTDIR}/network/connections.txt" # detect TCP
	
	# registry
	echo "[*] Searching for registry"
	mkdir -p "${RESULTDIR}/registry"
	./vol2 -f "$FILE" --profile=$PROF hivelist 2>/dev/null > "${RESULTDIR}/registry/hivelist.txt"  # list all registry hives
	
	mkdir -p "${RESULTDIR}/registry/reg_hives"
	./vol2 -f "$FILE" --profile=$PROF dumpregistry -D "${RESULTDIR}/registry/reg_hives" >/dev/null 2>&1 # extracts all hives at once
	
	./vol2 -f "$FILE" --profile=$PROF userassist 2>/dev/null > "${RESULTDIR}/registry/userassist.txt" # extract program execution count
	
	echo
	echo "[*] Created the folders:"
	echo "[1] processes"
	echo "[2] network" 
	echo "[3] registry"
	echo "[4] registry/reg_hives"
	echo "[!] The analyzed data is saved inside"
	echo
	
	echo "===================================="
	echo "Finished analyzing with volatility 2"
	echo "===================================="
	
	REPORT_ZIP "$FILE" "$RESULTDIR" "$TIME"
}

function VOLATILITY3_CHECK() # If vol3 was chosen - Check if the file is compatible with volatility 3
{
	sleep 1
	echo "-----------------------------"
	echo "Checking for compatibility..."
	echo "-----------------------------"
	echo	
	
	#if [ -z "$(vol -q -f "$FILE" windows.info | grep "Unable to validate the plugin requirements")" ]
	if vol -q -f "$FILE" windows.info >/dev/null 2>&1 
		then
			echo "------------------------------------------"
			echo "The file can be analyzed with volatility 3"
			echo "------------------------------------------"
			VOL3_ANA #if it is compatible - start analyzing
		return
	fi	
		echo
		echo "[!]This is not a supported file[!]"
		return
					
}		

function VOL3_ANA() # Execute volatility 3 with flags
{
	NAME=$(basename "$FILE")
	RESULTDIR="${NAME}_vol3_RESULT"
	TIME=$(date)
		
	echo "================="
	echo "STARTING ANALYSIS"
	echo "================="
	echo
	echo "------------------------------------------------------------"
	echo "Running volatility 3 and saving inside - ${RESULTDIR}"
	echo "------------------------------------------------------------"
	echo
	mkdir "${NAME}_vol3_RESULT"
	
	# basic information about the system
	echo "[*] Searching for basic system information"
	vol -q -f "$FILE" windows.info > "$RESULTDIR/windows_info.txt" 2>/dev/null
	
	# processes
	echo "[*] Searching for processes"
	mkdir -p "${RESULTDIR}/processes"
	vol -q -f "$FILE" windows.pslist > "$RESULTDIR/processes/windows_pslist.txt" 2>/dev/null # show active processes
	vol -q -f "$FILE" windows.psscan > "$RESULTDIR/processes/windows_psscan.txt" 2>/dev/null # show hidden terminated processes
	vol -q -f "$FILE" windows.pstree > "$RESULTDIR/processes/windows_pstree.txt" 2>/dev/null # show process tree
	
	# network
	echo "[*] Searching for network"
	mkdir -p "${RESULTDIR}/network"
	vol -q -f "$FILE" windows.netscan > "$RESULTDIR/network/windows_netscan.txt" 2>/dev/null # show network connection
	vol -q -f "$FILE" windows.netstat > "$RESULTDIR/network/windows_netstat.txt" 2>/dev/null # alternative scanner
	
	# registry
	echo "[*] Searching for registry"
	mkdir -p "${RESULTDIR}/registry"
	vol -q -f "$FILE" windows.registry.hivescan > "$RESULTDIR/registry/windows_hivescan.txt" 2>/dev/null # show registry structure
	vol -q -f "$FILE" windows.registry.hivelist > "$RESULTDIR/registry/windows_hivelist.txt" 2>/dev/null # show registry hives
	vol -q -f "$FILE" windows.registry.userassist > "$RESULTDIR/registry/windows_userassist.txt" 2>/dev/null # show executed programs
	
	echo
	echo "[*] Created the folders:"
	echo "[1] processes"
	echo "[2] network" 
	echo "[3] registry"
	echo "[!] The analyzed data is saved inside"
	echo
	
	echo "===================================="
	echo "Finished analyzing with volatility 3"
	echo "===================================="
	
	REPORT_ZIP "$FILE" "$RESULTDIR" "$TIME"
	
}	

function REPORT_ZIP() # Generate a report for the analysis and ZIP the results
{
	# rules
	FILE="$1"
    PARENTDIR="$2"
    TIME="$3"
	FILE_SIZE=$(du -sh "$PARENTDIR" | awk '{print $1}')	
	FILE_NUM=$(find "$PARENTDIR" -depth -type f | wc -l)
	{
		echo "============================================================="
		echo "*************************************************************"
		echo "                  FORENSIC ANALYSIS REPORT                   "
		echo "*************************************************************"
		echo
		echo "Analysis started at       : $TIME"
		echo "Report generated at       : $(date)"
		echo
		echo "Analyzed File             : $FILE"
		echo "Results location          : $PARENTDIR"
		echo "Results file size         : $FILE_SIZE"
		echo "Number of files inside    : $FILE_NUM"
		echo
		
		# stats:
		
		echo "============================================================="
		echo "                           STATS:                            "
		echo "============================================================="
		echo
		
		# binwalk
		if [ -f "$PARENTDIR/binwalk.txt" ]; then
			cd "$PARENTDIR"
			echo "The file *binwalk.txt* can be found inside:"
			pwd
			echo "The size of the file is: "
			ls -lh | grep binwalk | awk '{print $5}'
			echo
			cd ..
		fi
		# strings
		if [ -d "$PARENTDIR/strings" ]; then
			cd "$PARENTDIR/strings"
			echo "Files from *strings* can be found inside:"
			pwd
			echo "The size of the directory is:"
			ls -lh | grep total | awk '{print $2}'
			echo
			cd ..
			cd ..
		fi
		# foremost
		if [ -d "$PARENTDIR/foremost_output" ]; then
			cd "$PARENTDIR/foremost_output"
			echo "Files from *foremost* can be found inside:"
			pwd
			echo "The size of the directory is:"
			ls -lh | grep total | awk '{print $2}'
			echo
			cd ..
			cd ..
		fi
		# bulk_extractor
		if [ -d "$PARENTDIR/bulk_output" ]; then
			cd "$PARENTDIR/bulk_output"
			echo "Files from *bulk* can be found inside:"
			pwd
			echo "The size of the directory is:"
			ls -lh | grep total | awk '{print $2}'
			echo
			cd ..
			cd ..
		fi
		
		# vol2 + vol3
		# processes
		if [ -d "$PARENTDIR/processes" ]; then
			cd "$PARENTDIR/processes"
			echo "Files with *processes data* can be found inside:"
			pwd
			echo "The size of the directory is:"
			ls -lh | grep total | awk '{print $2}'
			echo
			cd ..
			cd ..
		fi
		# network
		if [ -d "$PARENTDIR/network" ]; then
			cd "$PARENTDIR/network"
			echo "Files with *network data* can be found inside:"
			pwd
			echo "The size of the directory is:"
			ls -lh | grep total | awk '{print $2}'
			echo
			cd ..
			cd ..
		fi
		# registry
		if [ -d "$PARENTDIR/registry" ]; then
			cd "$PARENTDIR/registry"
			echo "Files with *registry data* can be found inside:"
			pwd
			echo "The size of the directory is:"
			ls -lh | grep total | awk '{print $2}'
			echo
			cd ..
			cd ..
		fi
		# registry hives
		if [ -d "$PARENTDIR/registry/reg_hives" ]; then
			cd "$PARENTDIR/registry/reg_hives"
			echo "Files with *registry hives* can be found inside:"
			pwd
			echo "The size of the directory is:"
			ls -lh | grep total | awk '{print $2}'
			echo
			cd ..
			cd ..
			cd ..
		fi
			
		echo "============================================================="
		
	} > "$PARENTDIR/report.txt"
	
	echo
	echo "[!] REPORT FILE SAVED TO $PARENTDIR"  
	echo
	
	# zip the files together
	echo "-----------------------"
	echo "Creating ZIP Archive..."
	echo "-----------------------"
	zip -r "${PARENTDIR}.zip" "$PARENTDIR" >/dev/null 2>&1
	echo	
	echo "[!] ZIP Archive created and called ${PARENTDIR}.zip"
	echo	
}

function AGAIN() #Ask the user if to analyse another file
{
	echo "-------------------------------------"
	echo "Would you like to scan anything else?"
	echo "1. Yes"
	echo "2. No"
	echo "-------------------------------------"
	echo
	read again_answer
	case $again_answer in
		1)
			echo "***********"
			echo "No problem."
			echo "***********"
			echo 
			CHOICE
			AGAIN
		;;
		
		2)
			echo "********"
			echo "GOODBYE!"
			echo "********"
			exit
		;;
		
		*)
			echo "***************"
			echo "Invalid choice."
			echo "***************"
			AGAIN
		;;
		
	esac	
}
ROOT
APPS
CHOICE
AGAIN











