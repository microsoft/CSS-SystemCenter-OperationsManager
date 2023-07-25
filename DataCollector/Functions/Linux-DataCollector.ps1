function Start-LinuxDataCollector
{
	param
	(
		[Array]$Servers,
		[String]$Username
	)
    $Servers = ($Servers -split ",").Trim()
	# Last Updated: November 30th, 2022
	trap
	{
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	try
	{
		Get-Command -Name 'ssh' -ErrorAction Stop | Out-Null
		Write-Console " Found 'ssh' executable on the server"
		$foundSSH = $true
	}
	catch
	{
		Write-Warning "Unable to detect SSH client installed, you will need to either include plink (https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) in the SCOM Data Collector script folder, or you will need to install a SSH Client onto your machine and add it to the environmental variables so the 'ssh' command is accessible via Powershell.`n`nExiting.."
		#potential error code
		#use continue or break keywords
		$e = $_.Exception
		$line = $_.InvocationInfo.ScriptLineNumber
		$msg = $e.Message
		
		Write-Verbose "Caught Exception: $e :: Message: $msg :: at line: $line"
		"$(Invoke-TimeStamp)Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
		return
	}
	if (!$foundSSH)
	{
		try
		{
			Write-Console "  Testing to verify if the Plink executable is present."
			Test-Path "$ScriptPath\plink.exe" -ErrorAction Stop | Out-Null
		}
		catch
		{
			Write-Console "  Unable to locate plink.exe. Skipping Linux Data Collector gathering."
			"$(Invoke-TimeStamp)Unable to locate plink.exe. Skipping Linux Data Collector gathering." | Out-File $OutputPath\Error.log -Append
			break
		}
	}
	
	
	$ScomLinuxDataCollectorScript = @'
#! /bin/bash
#About:
#   This script is written for data collection from Linux machines which can help in troubleshooting SCOM UNIX/LINUX Agent (SCXAgent)
#Original Author :
#   Udish Mudiar, Microsoft Customer Service Support Professional
#Modified by :
#   Blake Drumm, Microsoft Customer Service Support Professional
#Feedback :
#   Email udmudiar@microsoft.com
#   Or the engineer you are working with
#How the data is transfered to Microsoft. We do secure transfer.
#https://docs.microsoft.com/en-US/troubleshoot/azure/general/secure-file-exchange-transfer-files
#

help(){
    printf "\nAbout:\n\tThis shell script is used to collect basic information about the Operating System and SCOM Linux (SCX) Agent"
    printf "\n\tThis is a read -r only script and does not make any changes to the system."
    printf "\n\nUsage: [OPTIONS]"
    printf "\n  Options:"
    printf "\n    -o  OutputPath : Specify the location where the data would be collected. If not specified the script will collect the data in the current working directory."
    printf "\n\n    -m  SCXMaintenanceAccount : Specify the SCX Maintenance Account. This will be used to check the sudo privilege for the account."
    printf "\n\n    -n  SCXMonitoringAccount : Specify the SCX Monitoring Account. This will be used to check the sudo privilege for the account.\n"
}

check_kernel(){
    printf "Checking kernel. The script will proceed only for supported kernel.....\n"
    printf "Checking kernel. The script will proceed only for supported kernel.....\n" >> "${path}"/scxdatacollector.log
    if [ "$(uname)" = 'Linux' ]; then
        printf "\tKernel is Linux. Continuing.....\n"
        printf "\tkernel is Linux. Continuing.....\n" >> "${path}"/scxdatacollector.log
    elif [ "$(uname)" = 'SunOS' ]; then
        printf "\tKernel is SunOS (Solaris). Continuing.....\n"
        printf "\tKernel is SunOS (Solaris). Continuing.....\n" >> "${path}"/scxdatacollector.log
    elif [ "$(uname)" = 'AIX' ]; then
        printf "\tKernel is AIX. Continuing.....\n"
        printf "\tKernel is AIX. Continuing.....\n" >> "${path}"/scxdatacollector.log
    else
        printf "\tDistro is not Linux/SunOS/AIX (Detected: %s). Exiting.....\n" "$(uname)"
        printf "\tDistro is not Linux/SunOS/AIX  (Detected: %s). Exiting.....\n" "$(uname)" >> "${path}"/scxdatacollector.log
        exit
    fi
}

check_parameters(){
    #checking the number of parameters passed
    #we expect either 1 or 2 parameters which are the SCOM maintenance and monitoring account
    #if the parameters passed are greater than 2 then it is advised that you recheck the SCOM Run As Account and Profiles for streamlining your configuration.
    #you can refer to he below blog:
    # https://udishtech.com/how-to-configure-sudoers-file-for-scom-monitoring/
    if [ $# == 1 ]; then
        printf "The argument for sudo is: $1.....\n"
        printf "The argument for sudo is: $1.....\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        check_sudo_permission "$1"
    elif [ $# == 2 ]; then
        printf "The arguments for sudo are : $1 and $2.....\n"
        printf "The arguments for sudo are : $1 and $2.....\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
        check_sudo_permission "$1" "$2"
    elif [ -z "${maint}" ] && [ -z "${mon}" ]; then
        printf "No SCOM Maintenance and Monitoring Account passed. Not collecting sudo details for the users....\n"
        printf "No SCOM Maintenance and Monitoring Account passed. Not collecting sudo details for the users....\n" >> "${path}"/scxdatacollector.log
        read -r -p 'Do you want to stop the script and rerun with the SCOM Accounts (Y/N)? ' response
       if [[ "${response}" == "Y" ]]; then
           printf "Exiting script....\n"
           exit 3
       elif [[ "${response}" == "N" ]]; then
            printf "Continuing script. But not collecting sudo details for the users....\n"
            printf "Continuing script. But not collecting sudo details for the users....\n" >> "${path}"/scxdatacollector.log
       fi
    fi
}

check_dir() {
    pwd=$(pwd)
    printf "Logs will be created in the output directory i.e. %s .....\n" "${path}"
    printf "Logs will be created in the output directory i.e. %s .....\n" "${path}" >> "${path}"/scxdatacollector.log
    printf "Creating the directory structure to store the data from the collector.....\n"
    printf "Creating the directory structure to store the data from the collector.....\n" >> "${path}"/scxdatacollector.log

    if [ -d "${path}/SCOMLinuxDataCollectorData" ]; then
        printf "\tPath %s/SCOMLinuxDataCollectorData is present. Removing and recreating the directory.....\n" "${path}"
        printf "\tPath %s/SCOMLinuxDataCollectorData is present. Removing and recreating the directory.....\n" "${path}" >> "${path}"/scxdatacollector.log
        sudo rm -rf "${path}"/SCOMLinuxDataCollectorData
        create_dir "${path}/SCOMLinuxDataCollectorData"
    else
        printf "\tPath ${pwd} is not present in the current working directory. Creating the directory.....\n"
        printf "\tPath ${pwd} is not present in the current working directory. Creating the directory.....\n" >> "${path}"/scxdatacollector.log
        create_dir "${path}/SCOMLinuxDataCollectorData"
    fi

    create_dir "${path}/SCOMLinuxDataCollectorData/logs"
    create_dir "${path}/SCOMLinuxDataCollectorData/certs"
    create_dir "${path}/SCOMLinuxDataCollectorData/network"
    create_dir "${path}/SCOMLinuxDataCollectorData/scxdirectorystructure"
    create_dir "${path}/SCOMLinuxDataCollectorData/pam"
    create_dir "${path}/SCOMLinuxDataCollectorData/scxprovider"
    create_dir "${path}/SCOMLinuxDataCollectorData/configfiles"
    create_dir "${path}/SCOMLinuxDataCollectorData/tlscheck"
    create_dir "${path}/SCOMLinuxDataCollectorData/core"
}

create_dir(){
    if [ -d "$1" ]; then
        printf "\tPath $1 exists. No action needed......\n"
        printf "\tPath $1 exists. No action needed......\n" >> "${path}"/scxdatacollector.log
    else
        printf "\tPath $1 does not exists. Proceed with creation.....\n"
        printf "\tPath $1 does not exists. Proceed with creation.....\n" >> "${path}"/scxdatacollector.log
        mkdir -p "$1"
    fi
}

collect_os_details() {
    printf "Collecting OS Details.....\n"
    printf "\nCollecting OS Details.....\n" >> "${path}"/scxdatacollector.log
    collect_host_name
    collect_os_version
    collect_system_logs sudo
    collect_compute
    collect_disk_space
    collect_network_details
    collect_openssl_details
    collect_openssh_details sudo
    collect_crypto_details
    check_kerberos_enabled
    collect_selinux_details
    collect_env_variable
    collect_readonly_variable    
    collect_other_config_files sudo
    collect_fips_details    #make this the last function call for readable output
}

collect_host_name() {
    printf "\tCollecting HostName Details.....\n"
    printf "\tCollecting Hostname Details.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******HOSTNAME******\n"  > "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    # below command works in all tested Kernel
    hostname >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    #below is what SCOM check while creating the self-signed certificate as CN
    printf "\n******HOSTNAME FOR CERTS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    # below command works in all tested Kernel
    nslookuphostname=$(nslookup "$(hostname)" | grep '^Name:' | awk '{print $2}' | grep "$(hostname)")
    if [ "${nslookuphostname}" ]; then
        printf "${nslookuphostname}" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    else
        printf "Unable to resolve hostname from nslookup." >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    fi
}

collect_os_version(){
    printf "\tCollecting OS Details.....\n"
    printf "\tCollecting OS Details.....\n" >> "${path}"/scxdatacollector.log
    printf "\n\n******OS VERSION******"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        printf "\nOS Kernel is Linux">> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        releasedata=$(cat /etc/*release)
	    releaseversion=$(printf "$releasedata" | grep -Po '(?<=PRETTY_NAME=")[^"]*')
	    printf "\t  Detected: ${releaseversion}"
        printf "$releasedata" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    elif [ "$kernel" == "SunOS" ]; then
        printf "\nOS Kernel is SunOS">> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        releasedata=$(cat /etc/*release)
	    releaseversion=$(printf "$releasedata" | grep -i "version=")
	    printf "\t  Detected: ${releaseversion}"
        printf "$releasedata" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    elif [ "$kernel" == "AIX" ]; then
        printf "\nOS Kernel is AIX">> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        oslevel=$(oslevel -s)
        releaseinfo=$(oslevel)	    
	    printf "\t  Detected: ${releaseinfo}"
        printf "$oslevel" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt        
    fi	
}

collect_compute(){
    printf "\n\tCollecting Memory and CPU for omi processes.....\n"
    printf "\tCollecting Memory and CPU for omi processes.....\n" >> "${path}"/scxdatacollector.log
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        printf "\n\n******MEM AND CPU FOR OMISERVER PROCESS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        ps -C omiserver -o %cpu,%mem,cmd >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******MEM AND CPU FOR OMIENGINE PROCESS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        ps -C omiengine -o %cpu,%mem,cmd >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******MEM AND CPU FOR OMIAGENT PROCESSES******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        ps -C omiagent -o %cpu,%mem,cmd >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    elif [[ "$kernel" == "SunOS" || "$kernel" == "AIX" ]]; then
        printf "\n\n******MEM AND CPU FOR OMISERVER PROCESS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        ps -efo pmem,pcpu,comm | grep -i omiserver >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******MEM AND CPU FOR OMIENGINE PROCESS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        ps -efo pmem,pcpu,comm | grep -i omiengine >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******MEM AND CPU FOR OMIAGENT PROCESSES******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        ps -efo pmem,pcpu,comm | grep -i omiagent >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt       
    fi    
}

collect_openssl_details() {
    printf "\tCollecting Openssl & Openssh Details.....\n"
    printf "\tCollecting Openssl & Openssh Details.....\n" >> "${path}"/scxdatacollector.log
    printf "\n******OPENSSL & OPENSSH VERSION******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    ssh -V  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt  2>&1 #this command is kernel agnostic
    printf "\n******OPENSSL VERBOSE******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    openssl version -a >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    printf "\n******OPENSSL CIPHERS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    openssl ciphers -v >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
}

collect_openssh_details(){
    printf "\tCollecting SSH Details.....\n"
    printf "\tCollecting SSH Details.....\n" >> "${path}"/scxdatacollector.log
    kernel=$(uname)
    if [[ "$kernel" == "Linux" || "$kernel" == "AIX" ]]; then
        #checking Kex settings in sshd. We are interested in the sshd server settings.
        printf "\n******SSH DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******KEY EXCHANGE ALGORITHIM (KEX) DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        $1 sshd -T | egrep ^kexalgorithms >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******CIPHERS DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        $1 sshd -T | grep ciphers >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******MACS DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        $1 sshd -T | grep macs >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n******HOST KEY ALGORITHIMS DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        $1 sshd -T | grep keyalgorithms >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        #copy the sshd configuration file
        printf "\n******Copying sshd config file******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        $1 cp -f /etc/ssh/sshd_config  "${path}"/SCOMLinuxDataCollectorData/configfiles/sshd_config_copy.txt
    elif [ "$kernel" == "SunOS" ]; then
        printf "\n******SSH DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        #SunOS does not have the sshd binary. Hence only copying the sshd config file
        printf "\n******Copying sshd config file******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        $1 cp -f /etc/ssh/sshd_config  "${path}"/SCOMLinuxDataCollectorData/configfiles/sshd_config_copy.txt     
    fi  
}

collect_disk_space(){
    printf "\tCollecting the file system usage.....\n"
    printf "\tCollecting the file system usage.....\n" >> "${path}"/scxdatacollector.log
    if [[ "$kernel" == "Linux" || "$kernel" == "SunOS" ]]; then        
        printf "\n******FILE SYSTEM DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        sudo df -h >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    elif [ "$kernel" == "AIX" ]; then        
        printf "\n******FILE SYSTEM DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        df -Pg >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt   
    fi   
}

check_kerberos_enabled(){
    #This is not a full proof method as there are 3rd party tools who uses different ways to enable Kerb auth. Need more testing.
    printf "\tChecking if Kerberos Authentication is enabled. This might not be 100%% accurate....\n"
    printf "\tChecking if Kerberos Authentication is enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
    if [ -f "/etc/krb5.conf" ]; then
        isKerb=$(cat /etc/krb5.conf | grep -E "^default_realm" | wc -l)
        if [ "${isKerb}" = 1 ]; then
            printf "\t  Kerberos Authentication is enabled. This might not be 100%% accurate....\n"
            printf "\t  Kerberos Authentication is enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
        else
            printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n"
            printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
        fi
    else
        printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n"
        printf "\t  Kerberos Authentication is not enabled. This might not be 100%% accurate....\n" >> "${path}"/scxdatacollector.log
    fi
}

collect_network_details(){
    printf "\tCollecting the network details.....\n"
    printf "\tCollecting the network details.....\n" >> "${path}"/scxdatacollector.log
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        printf "\n******IP ADDRESS DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails.txt        
        ip addr show>> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails.txt
        printf "\n******NETSTAT DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails.txt
        #netstat is a deprecated utility.
        ss >> "${path}"/SCOMLinuxDataCollectorData/network/netstatdetails.txt
    elif [[ "$kernel" == "SunOS" || "$kernel" == "AIX" ]]; then
        printf "\n******IP ADDRESS DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails.txt        
        ifconfig -a >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails.txt
        printf "\n******NETSTAT DETAILS******\n"  >> "${path}"/SCOMLinuxDataCollectorData/network/ipdetails.txt
        #netstat is a deprecated utility but present in SunOS and AIX
        netstat -an >> ${path}/SCOMLinuxDataCollectorData/network/netstatdetails          
    fi    
}

check_sudo_permission(){
    account_1=$(/bin/echo "$1")
    account_2=$(/bin/echo "$2")
   if (( $# == 1 )); then
        printf "Checking the sudo permissions for the account ${account_1}....\n"
        printf "Checking the sudo permissions for the account ${account_1}.....\n" >> "${path}"/scxdatacollector.log
        printf "\tChecking if ${account_1} is present....\n"
        printf "\tChecking if ${account_1} is present....\n" >> "${path}"/scxdatacollector.log
        count1=$(cat /etc/passwd | grep ${account_1} | wc -l)
        if [ "${count1}" = 1 ]; then
            printf "\t${account_1} is present...\n"
            printf "\t${account_1} is present.....\n" >> "${path}"/scxdatacollector.log
                    
            create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
            printf "******SUDO DETAILS FOR ${account_1}*****\n" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}.txt"
            sudo -l -U "${account_1}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}.txt"
        else
            printf "\t${account_1} is not present. Not checking sudo permission....\n"
            printf "\t${account_1} is not present. Not checking sudo permission....\n" >> "${path}"/scxdatacollector.log
        fi
   elif (( $# == 2 )); then
        printf "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n"
        printf "Checking the sudo permissions for the account ${account_1} and ${account_2}...\n" >> "${path}"/scxdatacollector.log
        printf "\tChecking if ${account_1} and ${account_2} are present...\n"
        printf "\tChecking if ${account_2} and ${account_2} are present.....\n" >> "${path}"/scxdatacollector.log
        count1=$(cat /etc/passwd | grep ${account_1} | wc -l)
        count2=$(cat /etc/passwd | grep ${account_2} | wc -l)
       
        if [ "${count1}" = 1 ] && [ "${count2}" = 1  ]; then
            printf "\t${account_1} and ${account_2} are present...\n"
            printf "\t${account_1} and ${account_2} are present.....\n" >> "${path}"/scxdatacollector.log
            
            create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
            printf "******SUDO DETAILS FOR %s*****\n" "${account_1}" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}.txt"
            sudo -l -U "${account_1}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}.txt"
            printf "******SUDO DETAILS FOR %s*****\n" "${account_2}" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_2}.txt"
            sudo -l -U "${account_2}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_2}.txt"
        elif [ "${count1}" = 1 ] && [ "${count2}" = 0 ]; then
            printf "\t${account_1} is present. ${account_2} is not present....\n"
            printf "\t${account_1} is present. ${account_2} is not present....\n" >> "${path}"/scxdatacollector.log

            create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
            printf "******SUDO DETAILS FOR %s*****\n" "${account_1}" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}.txt"
            sudo -l -U "${account_1}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_1}.txt"       
            
        elif [ "${count1}" = 0 ] && [ "${count2}" = 1 ]; then
            printf "\t${account_2} is present. ${account_1} is not present....\n"
            printf "\t${account_2} is present. ${account_1} is not present....\n" >> "${path}"/scxdatacollector.log  

            create_dir "${path}/SCOMLinuxDataCollectorData/sudo"
            printf "******SUDO DETAILS FOR %s*****\n" "${account_2}" > "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_2}.txt"
            sudo -l -U "${account_2}" >> "${path}"/SCOMLinuxDataCollectorData/sudo/"${account_2}.txt"      
           
        else
            printf "\t${account_1} and ${account_2} are not present. Not checking sudo permission....\n"
            printf "\t${account_1} and ${account_2} are not present. Not checking sudo permission.....\n" >> "${path}"/scxdatacollector.log
        fi
   fi
}

collect_crypto_details(){
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        #checking crypto only for Linux as of now. Because we are not sure whether AIX or SunOS has the crypto settings
        printf "\tCollecting Crypto details.....\n"
        printf "\tCollecting Crypto details.....\n" >> "${path}"/scxdatacollector.log
        if [ "$(which update-crypto-policie 2>/dev/null)" ]; then
            printf "\t\t Crypto binary found. Collecting the status....\n" >> "${path}"/scxdatacollector.log
            printf "*****CRYPTO SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
            update-crypto-policies --show >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        else
            printf "\t\t Crypto binary not found....\n" >> "${path}"/scxdatacollector.log
        fi             
    fi    
}

collect_selinux_details(){
    kernel=$(uname)
    # not applicable for other kernels.
    if [ "$kernel" == "Linux" ]; then
        printf "\tCollecting SELinux details.....\n"
        printf "\tCollecting SELinux details.....\n" >> "${path}"/scxdatacollector.log
        if [ "$(which sestatus 2>/dev/null)" ]; then
            printf "\t\t SELinux is installed. Collecting the status....\n" >> "${path}"/scxdatacollector.log
            printf "\n*****SELinux SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
            sestatus >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        else
            printf "\t\t SELinux is not installed....\n" >> "${path}"/scxdatacollector.log
        fi           
    fi    
}

collect_env_variable(){
    printf "\tCollecting env variable for the current user: $(whoami).....\n"
    printf "\tCollecting env variable for the current user: $(whoami).....\n" >> "${path}"/scxdatacollector.log
    # this command is kernel agnostic
    env >> "${path}"/SCOMLinuxDataCollectorData/configfiles/env.txt
}

collect_system_logs(){
    printf "\n\tCollecting system logs. Might take sometime. Hang On....."
    printf "\tCollecting system logs. Might take sometime. Hang On....." >> "${path}"/scxdatacollector.log
    #only copying the latest logs from the archive.
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        if [ -f "/var/log/messages" ]; then
            printf "\n\t\tFile /var/log/messages exists. Copying the file messages" >> "${path}"/scxdatacollector.log
            $1 cp -f /var/log/messages "${path}"/SCOMLinuxDataCollectorData/logs/messages_copy.txt
        else
            printf "\n\t\tFile /var/log/messages doesn't exists. No action needed" >> "${path}"/scxdatacollector.log 
        fi
        if [ -f "/var/log/secure" ]; then
            printf "\n\t\tFile /var/log/secure exists. Copying the file secure" >> "${path}"/scxdatacollector.log
            $1 cp -f /var/log/secure "${path}"/SCOMLinuxDataCollectorData/logs/secure_copy.txt
        else
            printf "\n\t\tFile /var/log/secure doesn't exists. No action needed" >> "${path}"/scxdatacollector.log   
        fi
        if [ -f "/var/log/auth" ]; then
            printf "\n\t\tFile /var/log/auth exists. Copying the file auth" >> "${path}"/scxdatacollector.log
            $1 cp -f /var/log/auth "${path}"/SCOMLinuxDataCollectorData/logs/auth_copy.txt
        else
            printf "\n\t\tFile /var/log/auth doesn't exists. No action needed" >> "${path}"/scxdatacollector.log  
        fi  
    elif [ "$kernel" == "SunOS" ]; then
        if [ -f "/var/log/authlog" ]; then
            printf "\n\t\tFile /var/log/authlog exists. Copying the file messages" >> "${path}"/scxdatacollector.log
            $1 cp -f /var/log/authlog "${path}"/SCOMLinuxDataCollectorData/logs/auth_copy.txt
        else
            printf "\n\t\tFile /var/log/authlog doesn't exists. No action needed" >> "${path}"/scxdatacollector.log 
        fi
        if [ -f "/var/log/syslog" ]; then
            printf "\n\t\tFile /var/log/syslog exists. Copying the file secure" >> "${path}"/scxdatacollector.log
            $1 cp -f /var/log/syslog "${path}"/SCOMLinuxDataCollectorData/logs/syslog_copy.txt
        else
            printf "\n\t\tFile /var/log/syslog doesn't exists. No action needed" >> "${path}"/scxdatacollector.log   
        fi
    elif [ "$kernel" == "AIX" ]; then
        if [ -f "/var/adm/ras/syslog.caa" ]; then
            printf "\n\t\tFile /var/adm/ras/syslog.caa. Copying the file messages" >> "${path}"/scxdatacollector.log
            $1 cp -f /var/adm/ras/syslog.caa "${path}"/SCOMLinuxDataCollectorData/logs/syslog.caa_copy.txt
        else
            printf "\n\t\tFile /var/adm/ras/syslog.caa doesn't exists. No action needed" >> "${path}"/scxdatacollector.log 
        fi
        if [ -f "/var/adm/ras/errlog" ]; then
            printf "\n\t\tFile /var/adm/ras/errlog exists. Copying the file secure" >> "${path}"/scxdatacollector.log
            $1 cp -f /var/adm/ras/errlog "${path}"/SCOMLinuxDataCollectorData/logs/err_copy.txt
        else
            printf "\n\t\tFile /var/adm/ras/errlog doesn't exists. No action needed" >> "${path}"/scxdatacollector.log   
        fi      
    fi	
    
}

collect_fips_details(){
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        printf "\tCollecting FIPS details......\n"
        printf "\n\n***************FIPS details************************\n" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        cat /proc/sys/crypto/fips_enabled >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        sysctl crypto.fips_enabled >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        printf "\n\nChecking if FIPS enabled machine has a file descriptor leak of omiserver......\n" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        sudo lsof -p $(ps -ef | grep -i omiserver | grep -v grep | awk '{print $2}') >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    fi
}

collect_readonly_variable(){
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        printf "\tCollecting Readonly variable in /etc/profile.d......\n"
        printf "\n\n***************Readonly Variable in /etc/profile.d************************\n" >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
        grep -R readonly /etc/profile.d >> "${path}"/SCOMLinuxDataCollectorData/OSDetails.txt
    fi
}

collect_other_config_files(){
    printf "\tCollecting other config files.....\n"
    printf "\tCollecting /etc/resolv.conf and /etc/hosts config files......\n" >> "${path}"/scxdatacollector.log
    #the below commands are kernel agnostic
    $1 cp -f /etc/resolv.conf "${path}"/SCOMLinuxDataCollectorData/configfiles/resolvconf_copy.txt
    $1 cp -f /etc/hosts "${path}"/SCOMLinuxDataCollectorData/configfiles/hosts_copy.txt
}

detect_installer(){
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        # If DPKG lives here, assume we use that. Otherwise we use RPM.
        printf "Checking installer should be rpm or dpkg.....\n" >> "${path}"/scxdatacollector.log
        type dpkg > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            installer=dpkg
            printf "\tFound dpkg installer....\n" >> "${path}"/scxdatacollector.log
            check_scx_installed $installer "$1"
        else
            installer=rpm
            printf "\tFound rpm installer......\n" >> "${path}"/scxdatacollector.log
            check_scx_installed $installer "$1"
        fi   
    elif [ "$kernel" == "SunOS" ]; then
        type pkg > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            installer=pkg
            printf "\tFound pkg installer....\n" >> "${path}"/scxdatacollector.log
            check_scx_installed $installer "$1"
        else            
            printf "\tpkg installer not found. Exiting.....\n" >> "${path}"/scxdatacollector.log
            ext
        fi 
    elif [ "$kernel" == "AIX" ]; then
        type lslpp > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            installer=lslpp
            printf "\tFound lslpp installer....\n" >> "${path}"/scxdatacollector.log
            check_scx_installed $installer "$1"
        else
            printf "\tlslpp installer not found. Exiting.....\n" >> "${path}"/scxdatacollector.log
            ext
        fi             
    fi    
}

check_scx_installed(){
    printf "Checking if SCX is installed.....\n"
    printf "Checking if SCX is installed.....\n" >> "${path}"/scxdatacollector.log
    #we will check if the installer is rpm or dpkg and based on that run the package command.
    if [ "$installer" == "rpm" ]; then
        scx=$(rpm -qa scx 2>/dev/null)
        if [ "$scx" ]; then
            printf "\tSCX package is installed. Collecting SCX details.....\n"
            printf "\tSCX package is installed. Collecting SCX details.....\n" >> "${path}"/scxdatacollector.log
            #calling function to gather more information about SCX
            collect_scx_details "$2"
        else
            printf "\tSCX package is not installed. Not collecting any further details.....\n" >> "${path}"/scxdatacollector.log
        fi
    #we will assume if not rpm than dpkg.
    elif [ "$installer" == "dpkg" ]; then
        scx=$(dpkg -s scx 2>/dev/null)
        if [ "$scx" ]; then
            printf "\tSCX package is installed. Collecting SCX details.....\n"
            printf "\tSCX package is installed. Collecting SCX details.....\n" >> "${path}"/scxdatacollector.log
            #calling function to gather more information about SCX
            collect_scx_details "$2"
        else
            printf "\tSCX package is not installed. Not collecting any further details.....\n" >> "${path}"/scxdatacollector.log
        fi
    elif [ "$installer" == "pkg" ]; then
        scx=$(pkginfo -l MSFTscx 2>/dev/null)
        if [ "$scx" ]; then
            printf "\tSCX package is installed. Collecting SCX details.....\n"
            printf "\tSCX package is installed. Collecting SCX details.....\n" >> "${path}"/scxdatacollector.log
            #calling function to gather more information about SCX
            collect_scx_details "$2"
        else
            printf "\tSCX package is not installed. Not collecting any further details.....\n" >> "${path}"/scxdatacollector.log
        fi
    elif [ "$installer" == "lslpp" ]; then
        scx=$(lslpp -l scx.rte 2>/dev/null)
        if [ "$scx" ]; then
            printf "\tSCX package is installed. Collecting SCX details.....\n"
            printf "\tSCX package is installed. Collecting SCX details.....\n" >> "${path}"/scxdatacollector.log
            #calling function to gather more information about SCX
            collect_scx_details "$2"
        else
            printf "\tSCX package is not installed. Not collecting any further details.....\n" >> "${path}"/scxdatacollector.log
        fi
    fi
}

collect_scx_details(){
    scxversion=$(scxadmin -version)
    scxstatus=$(scxadmin -status)
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        #netstat is a deprecated utility
        #netstat=`netstat -anp | grep :1270`
        netstatoutput=$(ss -lp | grep -E ":opsmgr|:1270") 
        omidstatus=$(systemctl status omid)
    elif [ "$kernel" == "SunOS" ]; then
        netstatoutput="Not supported for SunOS"
        omidstatus=$(svcs -l omid)     
    elif [ "$kernel" == "AIX" ]; then                
        netstatoutput=$(netstat -ano | grep 1270)
        omidstatus=$(lssrc -s omid)       
    fi    
    
    omiprocesses=$(ps -ef | grep [o]mi | grep -v grep)
    
    printf "\n*****SCX VERSION******\n" > "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${scxversion}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "\n*****SCX STATUS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${scxstatus}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "\n*****SCX PORT STATUS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${netstatoutput}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "\n*****OMI PROCESSES******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${omiprocesses}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "\n*****OMID STATUS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "${omidstatus}\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt

    #unable to figure out the redirection for now
    #if the omiserver is stopped then we need to check the status by running the utility
    #omiserverstatus=`/opt/omi/bin/omiserver`
    #printf "omiserver status:\n $omiserverstatus\n" >> ${path}/scxdatacollector.log

    #*****************************************
    #*********SCX FUNCTION CALLS**************
    #*****************************************
    collect_scx_config_files
    collect_omi_scx_logs
    collect_omi_scx_certs
    collect_scx_directories_structure "sudo"
    collect_omi_pam
    collect_scx_provider_status
    check_omi_core_files
    check_scx_omi_log_rotation
    test_tls_with_omi
    check_omiserver_dependencies
}

collect_scx_config_files(){
    printf "\tCopying config files.....\n"
    printf "\tCopying config files.....\n" >> "${path}"/scxdatacollector.log
    cp -f /etc/opt/omi/conf/omiserver.conf "${path}"/SCOMLinuxDataCollectorData/configfiles/omiserverconf_copy.txt
}

collect_omi_scx_logs(){
    printf "\tCollecting details of OMI and SCX logs.....\n"
    printf "\tCollecting details of OMI and SCX logs.....\n" >> "${path}"/scxdatacollector.log
    omilogsetting=$(cat /etc/opt/omi/conf/omiserver.conf | grep -i loglevel)
    printf "\n*****OMI LOG SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "$omilogsetting \n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    scxlogsetting=$(scxadmin -log-list)
    printf "\n*****SCX LOG SETTINGS******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    printf "$scxlogsetting \n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt

    printf "\tCopying OMI and SCX logs. Might take sometime. Hang On....\n"
    printf "\tCopying OMI and SCX logs. Might take sometime. Hang On....\n" >> "${path}"/scxdatacollector.log
    count1=$(ls -1 /var/opt/omi/log/*.log  2>/dev/null | wc -l)
    if [ "${count1}" -ne 0 ]; then
      printf "\t\tFound .log files in path /var/opt/omi/log. Copying the logs.. \n" >> "${path}"/scxdatacollector.log
      cp -f /var/opt/omi/log/*.log "${path}"/SCOMLinuxDataCollectorData/logs
    else
      printf "\t\tNo .log files found in path /var/opt/omi/log. No action needed....\n" >> "${path}"/scxdatacollector.log
    fi

    count2=$(ls -1 /var/opt/omi/log/*.trc  2>/dev/null | wc -l)    
    if [ "${count2}" -ne 0 ]; then
        printf "\t\tFound .trc files in path /var/opt/omi/log. Copying the logs.. \n" >> "${path}"/scxdatacollector.log
        cp -f /var/opt/omi/log/*.trc "${path}"/SCOMLinuxDataCollectorData/logs
    else
        printf "\t\tNo .trc files found in path /var/opt/omi/log. No action needed.... \n" >> "${path}"/scxdatacollector.log
    fi

    count3=$(ls -1 /var/opt/microsoft/scx/log/*.log  2>/dev/null | wc -l)
    if [ "${count3}" -ne 0 ]; then
        printf "\t\tFound .log files in path /var/opt/microsoft/scx/log/*.log. Copying the logs.. \n" >> "${path}"/scxdatacollector.log
        cp -f /var/opt/microsoft/scx/log/*.log "${path}"/SCOMLinuxDataCollectorData/logs
    else
        printf "\t\tNo .log files found in path /var/opt/microsoft/scx/log/*.log. No action needed.... \n" >> "${path}"/scxdatacollector.log
    fi
}

collect_omi_scx_certs(){
    printf "\tCollecting SCX cert details.....\n"
    printf "\tCollecting SCX cert details.....\n" >> "${path}"/scxdatacollector.log

    #checking omi certs
    if [ -d "/etc/opt/omi/ssl/" ]; then
      printf "\t \tPath /etc/opt/omi/ssl exists. Dumping details.....\n" >> "${path}"/scxdatacollector.log
      #dumping the list of files as the soft links can be broken at times of the permissions might be messed
      printf "\n******OMI CERTS STRUCTURE******\n" >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt
      ls -l /etc/opt/omi/ssl/ >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt

      cert=$(ls /etc/opt/omi/ssl/)
      omipubliccertsoftlink=$(find /etc/opt/omi/ssl | grep omi.pem)

      #checking the omi.pem
        if [ -f "${omipubliccertsoftlink}" ]; then
            printf "\t\tomi public cert exists.....\n" >> "${path}"/scxdatacollector.log
        else
            printf "\t\tomi public cert does not exists.....\n" >> "${path}"/scxdatacollector.log
        fi
    else
      printf "\t\tPath /etc/opt/omi/ssl does not exists.....\n" >> "${path}"/scxdatacollector.log
    fi

    #checking scx certs
    if [ -d "/etc/opt/microsoft/scx/ssl/" ]; then
        printf "\t\tPath /etc/opt/microsoft/scx/ssl/ exists. Dumping details.....\n" >> "${path}"/scxdatacollector.log
        printf "\n******SCX CERT STRUCTURE******\n" >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt
        ls -l /etc/opt/microsoft/scx/ssl/ >> "${path}"/SCOMLinuxDataCollectorData/certs/certlist.txt

        scxpubliccertsoftlink=$(find /etc/opt/microsoft/scx/ssl | grep scx.pem)
        #checking the scx.pem
        #dumping scx.pem as SCOM uses it.
        if [ -f "${scxpubliccertsoftlink}" ]; then
            printf "\t\tscx public cert exists..Dumping details.....\n" >> "${path}"/scxdatacollector.log
            openssl x509 -in /etc/opt/microsoft/scx/ssl/scx.pem -text > "${path}"/SCOMLinuxDataCollectorData/certs/certdetails_long.txt
            openssl x509 -noout -in /etc/opt/microsoft/scx/ssl/scx.pem  -subject -issuer -dates > "${path}"/SCOMLinuxDataCollectorData/certs/certdetails_short.txt
        else
            printf "\t\tscx public cert does not exists.....\n" >> "${path}"/scxdatacollector.log
        fi
    else
        printf "\t\tPath /etc/opt/microsoft/scx/ssl/ does not exists.....\n" >> "${path}"/scxdatacollector.log
    fi
}

collect_scx_directories_structure(){
    printf "\tCollecting SCX DirectoryStructure.....\n"
    printf "\tCollecting SCX DirectoryStructure.....\n" >> "${path}"/scxdatacollector.log
    $1 ls -lR /var/opt/microsoft/ >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-microsoft.txt
    $1 ls -lR /var/opt/omi >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/var-opt-omi.txt
    $1 ls -lR /opt/omi/ >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/opt-omi.txt
    $1 ls -lR /etc/opt/microsoft/ >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-microsoft.txt
    $1 ls -lR /etc/opt/omi >> "${path}"/SCOMLinuxDataCollectorData/scxdirectorystructure/etc-opt-omi.txt
}

collect_omi_pam(){
    printf "\tCollecting omi PAM details.....\n"
    printf "\tCollecting omi PAM details.....\n" >> "${path}"/scxdatacollector.log
    if [ -f /etc/pam.conf ]; then
        # PAM configuration file found; use that
        # This is probably Solaris or AIX
        cp -f /etc/pam.conf "${path}"/SCOMLinuxDataCollectorData/pam/pamconf.txt
    elif [ -f /etc/pam.d/omi ]; then
        #this should be Linux
        cp -f /etc/pam.d/omi "${path}"/SCOMLinuxDataCollectorData/pam/omi.txt
        #also collecting dependent pam files. Not comphrensive list of files though.
        cp -f /etc/pam.d/password-auth "${path}"/SCOMLinuxDataCollectorData/pam/password-auth.txt
        cp -f /etc/pam.d/postlogin "${path}"/SCOMLinuxDataCollectorData/pam/postlogin.txt
    fi
}

collect_scx_provider_status(){
   printf "\tCollecting SCX Provider Details. **If this step is hung, press Ctrl+C to forcefully exit....\n"
   printf "\tCollecting SCX Provider Details.....\n" >> "${path}"/scxdatacollector.log
   if [ -d "/etc/opt/omi/conf/omiregister" ]; then
      printf "\t\tomiregister directory found. Collecting more details.....\n" >> "${path}"/scxdatacollector.log
      cp /etc/opt/omi/conf/omiregister/root-scx/* "${path}"/SCOMLinuxDataCollectorData/scxprovider
   else
      printf "\t\tomiregister directory not found......\n" >> "${path}"/scxdatacollector.log
   fi

   printf "\t\tQuery the omi cli and dumping details for one class from each identity (root, req, omi).....\n" >> "${path}"/scxdatacollector.log
   #We can think of dumping all the classes information if required.
   #However, we need to keep in mind if the provider is hung then we have to kill the query after sometime. That logic has to be built later.
   /opt/omi/bin/omicli ei root/scx SCX_UnixProcess >> "${path}"/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus.txt
   /opt/omi/bin/omicli ei root/scx SCX_Agent >> "${path}"/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus.txt
   /opt/omi/bin/omicli ei root/scx SCX_OperatingSystem >> "${path}"/SCOMLinuxDataCollectorData/scxprovider/scxproviderstatus.txt
}

check_omi_core_files(){
   printf "\tCheck for core files in SCX directory /var/opt/omi/run/.....\n"
   printf "\tCheck for core files in SCX directory /var/opt/omi/run/......\n" >> "${path}"/scxdatacollector.log   
    
    kernel=$(uname)
    if [ "$kernel" == "Linux" ]; then
        if [ "$(cat /etc/*release | grep -E "^NAME" | grep -i "Red Hat" | wc -l)" -eq 1 ]; then
            echo "\t\tRed Hat Detected.... " >> "${path}"/scxdatacollector.log
            #RHEL8 onwards has seperate mechanisms to log core file.
            if [ "$(cat /etc/*release | grep VERSION_ID | cut -d "=" -f 2 | sed  's/"//' | sed  's/"//' | cut -d "." -f 1)" -gt 7 ]; then
                echo "Red Hat 8+ detected...." >> "${path}"/scxdatacollector.log
                corefilescount=$(ls -1 /var/lib/systemd/coredump/core.omi* 2>/dev/null | wc -l)
                if [ "${corefilescount}" -ne 0 ]; then
                    printf "\t\tFound core files in path /var/lib/systemd/coredump. Copying the core files.. \n" >> "${path}"/scxdatacollector.log
                    cp -f /var/lib/systemd/coredump/core.omi* "${path}"/SCOMLinuxDataCollectorData/core
                else
                    printf "\t\tNo core files found in path /var/lib/systemd/coredump. No action needed....\n" >> "${path}"/scxdatacollector.log
                fi                
            fi
        #for other Linux distro using the default
        else
            corefilescount=$(ls -1 /var/opt/omi/run/core* 2>/dev/null | wc -l)
            if [ "${corefilescount}" -ne 0 ]; then
                printf "\t\tFound core files in path /var/opt/omi/run/. Copying the core files.. \n" >> "${path}"/scxdatacollector.log
                cp -f /var/opt/omi/run/core* "${path}"/SCOMLinuxDataCollectorData/core
            else
                printf "\t\tNo core files found in path /var/opt/omi/run/. No action needed....\n" >> "${path}"/scxdatacollector.log
            fi
        fi
    else
        corefilescount=$(ls -1 /var/opt/omi/run/core* 2>/dev/null | wc -l)
        if [ "${corefilescount}" -ne 0 ]; then
            printf "\t\tFound core files in path /var/opt/omi/run/. Copying the core files.. \n" >> "${path}"/scxdatacollector.log
            cp -f /var/opt/omi/run/core* "${path}"/SCOMLinuxDataCollectorData/core
        else
            printf "\t\tNo core files found in path /var/opt/omi/run/. No action needed....\n" >> "${path}"/scxdatacollector.log
        fi
    fi   
}

check_scx_omi_log_rotation(){
    printf "\tChecking the log rotation configuration for omi and scx.....\n"
    printf "\tChecking the log rotation configuration for omi and scx......\n" >> "${path}"/scxdatacollector.log
    if [ -f "/etc/opt/omi/conf/omilogrotate.conf" ]; then
        printf "\tFound omilogrotate.conf in path /etc/opt/omi/conf. Copying the file.. \n" >> "${path}"/scxdatacollector.log
        cp -f /etc/opt/omi/conf/omilogrotate.conf  "${path}"/SCOMLinuxDataCollectorData/configfiles/omilogrotateconf_copy.txt
    else
        printf "\tNot found omilogrotate.conf in path /etc/opt/omi/conf...... \n" >> "${path}"/scxdatacollector.log
    fi
    if [ -f "/etc/opt/microsoft/scx/conf/logrotate.conf" ]; then
        printf "\tFound logrotate.conf in path /etc/opt/microsoft/scx/conf. Copying the file.. \n" >> "${path}"/scxdatacollector.log
        cp -f /etc/opt/microsoft/scx/conf/logrotate.conf  "${path}"/SCOMLinuxDataCollectorData/configfiles/scxlogrotateconf_copy.txt
    else
        printf "\tNot found omilogrotate.conf in path /etc/opt/microsoft/scx/conf. Copying the file.. \n" >> "${path}"/scxdatacollector.log
    fi 
}

test_tls_with_omi(){
    printf "\tTesting TLS 1.0, 1.1 and 1.2 on port 1270 locally. Might take sometime. Hang On.........\n"
    printf "\tTesting TLS 1.0, 1.1 and 1.2 on port 1270 locally. Might take sometime. Hang On..........\n" >> "${path}"/scxdatacollector.log
    openssl s_client -connect localhost:1270 -tls1 < /dev/null > "${path}"/SCOMLinuxDataCollectorData/tlscheck/tls1.txt 2> /dev/null
    openssl s_client -connect localhost:1270 -tls1_1 < /dev/null > "${path}"/SCOMLinuxDataCollectorData/tlscheck/tls1.1.txt 2> /dev/null
    openssl s_client -connect localhost:1270 -tls1_2 < /dev/null > "${path}"/SCOMLinuxDataCollectorData/tlscheck/tls1.2.txt 2> /dev/null
}

check_omiserver_dependencies(){
    printf "\tCollecting dependencies of omiserver.........\n"
    printf "\tCollecting dependencies of omiserver.........\n" >> "${path}"/scxdatacollector.log
    printf "\n*****LDD******\n" >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
    ldd /opt/omi/bin/omiserver >> "${path}"/SCOMLinuxDataCollectorData/SCXDetails.txt
}

archive_logs () {
   printf "\nSuccessfully completed the SCOM Linux Data Collector.....\n" >> "${path}"/scxdatacollector.log
   count=$(ls ${path}/SCOMLinuxDataCollectorData*.tar.gz 2>/dev/null | wc -l)
   if [ $count -ne 0 ]; then   
      printf "File SCOMLinuxDataCollectorData*.tar.gz already exist. Cleaning up before new archive.....\n"
      printf "File SCOMLinuxDataCollectorData*.tar.gz already exist. Cleaning up before new archive.....\n"  >> "${path}"/scxdatacollector.log
      sudo rm -rf "${path}"/SCOMLinuxDataCollectorData*.tar.gz
   fi

   printf "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData.\n"
   printf "Moving the scxdatacollector.log file to SCOMLinuxDataCollectorData. Archiving and zipping SCOMLinuxDataCollectorData. Cleaning up other data....\n" >> "${path}"/scxdatacollector.log
   echo -e "\n $(date) Successfully completed the SCOM Linux Data Collector steps. Few steps remaining....\n" >> "${path}"/scxdatacollector.log
   mv "${path}"/scxdatacollector.log "${path}"/SCOMLinuxDataCollectorData
   printf "Archiving and zipping SCOMLinuxDataCollectorData. Might take sometime. Hang On.....\n"
   dateformat=$(date +%d%m%Y)
   tar -cf "${path}"/SCOMLinuxDataCollectorData_$(hostname)_$dateformat.tar "${path}"/SCOMLinuxDataCollectorData 2> /dev/null

   gzip "${path}"/SCOMLinuxDataCollectorData*.tar
   printf "Clean up other data....\n"
   sudo rm -rf "${path}"/SCOMLinuxDataCollectorData.tar
   sudo rm -rf "${path}"/SCOMLinuxDataCollectorData
}

#this function fetches the maximum information
sub_main_root(){
    check_dir "$path"
    collect_os_details    
	if [ -n "$maint" ] || [ -n "$mon" ]; then
        if [ -n "$maint" ] && [ -n "$mon" ]; then
             check_sudo_permission "$maint" "$mon"
        elif [ -z "$mon" ]; then
             check_sudo_permission "$maint" 
        elif [ -z "$maint" ]; then
             check_sudo_permission "$mon" 
        fi       
	else
		printf "Checking the sudo permissions\n"
        printf "\tNo accounts passed as argument. Not checking sudo permissions.....\n"
	fi
    #this call will also check the scx components
    detect_installer
    #This has to be the last function call in the script
    archive_logs
}

#this function fetches the less information
sub_main_non_root(){
    check_dir "$path"
    collect_os_details
	if [ -n "$maint" ] || [ -n "$mon" ]; then
        if [ -n "$maint" ] && [ -n "$mon" ]; then
             check_sudo_permission "$maint" "$mon"
        elif [ -z "$mon" ]; then
             check_sudo_permission "$maint" 
        elif [ -z "$maint" ]; then
             check_sudo_permission "$mon" 
        fi       
	else
		printf "Checking the sudo permissions\n"
        printf "\tNo accounts passed as argument. Not checking sudo permissions....."
	fi
    #this call will also check the scx components
    detect_installer sudo
    #This has to be the last function call in the script
    archive_logs
}

main(){
    printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    #clearing the scxdatacollector.log file to start with
    #using sudo out-of-box even if the user is root to avoid permission denied on the intial log file creation.   

    if [ -z "${path}"  ]; then
        path=$(pwd)
        if [ $(whoami) = "root" ]; then
            printf "" > "${path}"/scxdatacollector.log 
            printf "Log Collection Path is NULL. Setting Path to current working directory......\n"
            printf "Log Collection Path is NULL. Setting Path to current working directory......\n" >> "${path}"/scxdatacollector.log
        else
            ls -ld $path
            echo "Does the output path has write access for the sudo user $(whoami)?(Y/N)"
            read answer        
            if [ "${answer}" = "N" ]; then
                echo "Do you want to set the write permission on the path for the current user and continue?(Y/N)"
                read answer  
                if [ "${answer}" = "Y" ]; then
                    sudo chmod o+w $path
                elif [ "${answer}" = "N" ]; then
                    echo "Exiting script. Provide the write access on the output path and rerun the script. Or output it to a directory which has write access to the user"
                    exit
                fi            
            elif [ "${answer}" = "Y" ]; then  
                sudo printf "" > "${path}"/scxdatacollector.log 
                printf "Log Collection Path is NULL. Setting Path to current working directory......\n"
                printf "Log Collection Path is NULL. Setting Path to current working directory......\n" >> "${path}"/scxdatacollector.log        
            fi   
        fi        
    else
        if [ $(whoami) = "root" ]; then
            printf "" > "${path}"/scxdatacollector.log 
            printf "Log Collection Path is NULL. Setting Path to current working directory......\n"
            printf "Log Collection Path is NULL. Setting Path to current working directory......\n" >> "${path}"/scxdatacollector.log
        else
            ls -ld $path
            echo "Does the output path has write access for the sudo user $(whoami)?(Y/N)"
            read answer        
            if [ "${answer}" = "N" ]; then
                echo "Do you want to set the write permission on the path for the current user and continue?(Y/N)"
                read answer  
                if [ "${answer}" = "Y" ]; then
                    sudo chmod o+w $path
                elif [ "${answer}" = "N" ]; then
                    echo "Exiting script. Provide the write access on the output path and rerun the script. Or output it to a directory which has write access to the user"
                    exit
                fi            
            elif [ "${answer}" = "Y" ]; then  
                sudo printf "" > "${path}"/scxdatacollector.log 
                printf "Log Collection Path is NULL. Setting Path to current working directory......\n"
                printf "Log Collection Path is NULL. Setting Path to current working directory......\n" >> "${path}"/scxdatacollector.log        
            fi   
        fi          
    fi

    #Currently supporting SCX 2016+ versions
    printf "Starting the SCOM Linux Data Collector.....\nDisclaimer: Currently supporting SCX 2016+ versions\n"
    printf "$(date)Starting the SCOM Linux Data Collector.....\n" > "${path}"/scxdatacollector.log
    printf "The script name is: $0\n" > "${path}"/scxdatacollector.log
    printf "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n"
    printf "The arguments passed are: \n Path = ${path} \n Maint = ${maint} \n Mon = ${mon} \n" >> "${path}"/scxdatacollector.log

    #checking the kernel. Will only continue in supported kernel
    check_kernel

    #fetching the user under which the script is running.
    user="$(whoami)"
    printf "Script is running under user: ${user}.....\n"
    printf "Script is running under user: ${user}.....\n" >> "${path}"/scxdatacollector.log
    if [ "$user" = 'root' ]; then
         printf "\tUser is root. Collecting maximum information.....\n"
         sub_main_root "$path" "$maint" "$mon"
    else
         printf "\tUser is non root. Collecting information based on the level of privilege.....\n"         
         sub_main_non_root "$path" "$maint" "$mon"
    fi
}

############################################################
# Script execution starts from here.                       #
############################################################


############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts "ho:m:n:" option; do
   case $option in
      h) # display Help
         help
         exit;;
      o) # Enter log collection path
         path=$OPTARG
         ;;
      m) # Enter log collection path
         maint=$OPTARG
         ;;
      n) # Enter log collection path
         mon=$OPTARG
         ;;
     \?) # Invalid option
         printf "Error: Invalid option - Run help (-h) for full parameters"
         exit;;
   esac
done

#function calls
        main "$path" "$maint" "$mon"


printf "\n****************************************************************************************************************************************************"
printf "\n********************************************************REVIEW**************************************************************************************"
printf "\n****************************************************************************************************************************************************"
printf "\nThe collected zip file may contain personally identifiable or security related information, including but not necessarily limited to host names,"
printf "\nIP addresses, hosts file, resolve.conf file, environment variable, openssh configuration etc."
printf "\nThe collect zip file DOES NOT contain information like users, groups, firewall, sudo file details etc."
printf "\nBy uploading the zip file to Microsoft Support you accept that you are aware of the content of the zip file. If you have Data Privacy Guidelines"
printf "\nwithin your organization, please remove the content, you do not wish you upload."
printf "\n****************************************************************************************************************************************************"
printf "\n\nSuccessfully completed the SCOM Linux Data Collector.\n"
printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"


: '
MIT License

Copyright (c) 2023 Udish Mudiar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 '
'@	
    function ConvertTo-LinuxLineEndings($path) {
        $oldBytes = [io.file]::ReadAllBytes($path)
        if (!$oldBytes.Length) {
            return;
        }
        [byte[]]$newBytes = @()
        [byte[]]::Resize([ref]$newBytes, $oldBytes.Length)
        $newLength = 0
        for ($i = 0; $i -lt $oldBytes.Length - 1; $i++) {
            if (($oldBytes[$i] -eq [byte][char]"`r") -and ($oldBytes[$i + 1] -eq [byte][char]"`n")) {
                continue;
            }
            $newBytes[$newLength++] = $oldBytes[$i]
        }
        $newBytes[$newLength++] = $oldBytes[$oldBytes.Length - 1]
        [byte[]]::Resize([ref]$newBytes, $newLength)
        [io.file]::WriteAllBytes($path, $newBytes)
    }
	try
	{
		$ScomLinuxDataCollectorScript | Out-File -Force -Encoding utf8 -FilePath "$ScriptPath\SCOMLinuxDataCollector.sh" -ErrorAction Stop
        ConvertTo-LinuxLineEndings -Path "$ScriptPath\SCOMLinuxDataCollector.sh"
	}
	catch
	{
		Write-Console "  Unable to create / write to the following path: '$ScriptPath\SCOMLinuxDataCollector.sh'"
		"$(Invoke-TimeStamp)Unable to create / write to the following path: '$ScriptPath\SCOMLinuxDataCollector.sh' :: Caught Exception: $e :: Message: $msg :: at line: $line" | Out-File $OutputPath\Error.log -Append
	}
	foreach ($LinuxServer in $Servers)
	{
		if (-NOT ($Username))
        {
            do
            {
                $Username = Read-Host "Please type the Username to be used for connection to the Linux Server: $LinuxServer"
            }
            until ($Username)
        }
		# TAKE INTO CONSIDERATION - DIFFERENT SSH PORT 
		Write-Console "  Copying script to remote Unix/Linux server: $LinuxServer"
		scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$ScriptPath\SCOMLinuxDataCollector.sh" $Username`@$LinuxServer`:./
        
		Write-Console "  Attempting to run script on remote Unix/Linux server: $LinuxServer"
		ssh $Username`@$LinuxServer 'chmod +x ./SCOMLinuxDataCollector.sh; sudo sh ./SCOMLinuxDataCollector.sh'

        Write-Console "  Creating folder for the output from the SCOM Linux Data Collector gathering on: $LinuxServer"
        New-Item -ItemType Directory -Path "$ScriptPath\Output\Linux Data Collector\$LinuxServer" | Out-Null

        Write-Console "  Attempting to copy script output from remote server to local management server: $LinuxServer"
        scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $Username`@$LinuxServer`:./SCOMLinuxDataCollectorData.tar.gz "$ScriptPath\Output\Linux Data Collector\$LinuxServer\SCOMLinuxDataCollectorData-$LinuxServer.tar.gz"
	}
	
}
