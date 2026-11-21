import re 


def load_data (filename):

    data=[]
    try:
        with open(filename, "r") as file:
            for line in file:
                line=line.strip()

                if not line:
                    continue
                data.append(line)

    except FileNotFoundError:
        print(f"UNABLE TO LOCATE {filename}")
        return [] 
    
    except Exception as e: 
        print(" UNEXPECTED ERROR OCCURED", e)
        return[]

    return data

def load_suspicious_ips(filepath="suspicious_ips.txt"):
    try:
        with open(filepath, "r") as file:
            return set(file.read().splitlines())
    except FileNotFoundError:
        print(f"FILE NOT FOUND. EMPTY SET PROVIDED")
        return set()

    except Exception as e: #<--- catch all error handeling
        print(" UNEXPECTED ERROR OCCURED", e)
        return set()

def analyse_firewall_data(data):

    print("FIREWALL ANALYSIS")


######            ######
###### IP SECTION ######
######            ######


###### ALLOWED / BLOCKED COUNTER (LAB4 A1) #######

    print("\n########## IP ADDRESS DATA BREAKDOWN ###########")

    try:
        if not data:
            print ("FIREWALL.LOG DATA IS NOT AVAILABLE")
            return 
    

        print("\n ALLOWED - BLOCKED - MALFORMED LINES COUNT ")
        
        allowed_count=0
        blocked_count=0
        malformed_count=0

        try:
            
            for line in data:
                if "ALLOWED" in line:
                    allowed_count = allowed_count + 1
                elif "BLOCKED" in line:
                    blocked_count = blocked_count + 1
                else:
                    malformed_count =malformed_count + 1

            print (f"\nNUMBER OF ALLOWED CONNECTIONS {allowed_count}")
            print (f"\nNUMBER OF BLOCKED CONNECTIONS {blocked_count}")
            print (f"\nNUMBER OF MALFORMED LINES {malformed_count}")

        except Exception as e:
            print("UNEXPECTED ERROR HAS OCCURED", e)

        

    ####### MOST OCCURING IP ADDRESS (LAB4 A2/B3) #######

        print("\n MOST OCCURING BLOCKED IP ADDESSES ")


        ip_count= {} 
        blocked_ip_count={}
        pattern= r"src=(\d{1,3}(?:\.\d{1,3}){3})"

        for line in data:
            
                match=re.search(pattern, line) 
                if match:                       
                    ip=match.group(1)          

                    if ip not in ip_count: 
                        ip_count[ip]=0
                    ip_count[ip]+=1


                    if "BLOCKED" in line: 
                        if ip not in blocked_ip_count:
                            blocked_ip_count[ip] = 0 
                        blocked_ip_count[ip]+=1 



        most_occuring_ip=[]        

        if blocked_ip_count:
            most_occuring_ip=sorted(blocked_ip_count, key=blocked_ip_count.get, reverse=True)[:5] #<--- can be changed to any amount depening on log entries

            for ip in most_occuring_ip:
                print (f"\n IP : {ip} \n OCCURED: ({blocked_ip_count[ip]}) TIMES")


    ######## UNIQUE IP ADDESSES ##########


        unique_ip_count=len(ip_count) 
        print(f"\nNUMBER OF UNIQUE IPs: {unique_ip_count}")


    ######              ######
    ###### PORT SECTION ######
    ######              ######


    ###### COMMENLY TARGETED DESTINATION PORTS ######


        print ("\n######### PORT DATA BREAKDOWN ##########")

        print ("\n COMMENLY TARGETED DESTINATION PORTS")

        port_count = {}
        port_pattern = r"port=(\d{1,5})"

        for line in data:
            if "BLOCKED" in line:
                match = re.search(port_pattern, line)
                if match:
                    port=match.group(1)

                    if port not in port_count:
                        port_count[port]= 0
                    port_count[port]+=1
        

        most_common_port=[]

        if port_count:
            most_common_port=sorted(port_count, key=port_count.get, reverse=True)[:10]


            for port in most_common_port:
                print(f"\n DESTINATION PORT: {port} \n OCCURED ({port_count[port]}) TIMES")


    ########## SUSPICIOUS IP ADDRESSES ##########

        print("\n################ SUSPICIOUS IP ADDRESS BREAKDOWN ##############")

        suspicious_ips=load_suspicious_ips() 

        print("\n ALERT : FIREWALL.LOG HAS MATCHES TO SUSPICIOUS_IPS.TXT")

        matched_ips=[]

        for ip in ip_count:
            if ip in suspicious_ips:
                matched_ips.append(ip) 

        if matched_ips:
            for sus_ip in matched_ips:
                print(f"\nIP ADDRESS: {sus_ip} - \n APPEARS {ip_count[sus_ip]} TIMES ")
        else:
                print("NO MATCHES TO SUSPICIOUS_IPS.TXT HAVE BEEN FOUND")

        ############ RETURNING RESULTS #############
        return {
            "ALLOWED COUNT" : allowed_count,
            "BLOCKED COUNT" : blocked_count,
            "MALFORMED COUNT": malformed_count,
            "UNIQUE IPs": unique_ip_count,
            "MOST OCCURING BLOCKED IPs": {ip: blocked_ip_count[ip] for ip in most_occuring_ip},
            "MOST TARGETED PORTS": {port: port_count[port] for port in most_common_port},
            "SUSPICIOUS MATCHES": {ip: ip_count[ip] for ip in matched_ips}
        }

    except Exception as e:
        print("UNEXPECTED ERROR HAS OCCURED", e)
            
def analyse_authentication_data(data):

    ###### SUCCESS / FAILED COUNTER (LAB4 A1) #######

    print("\nAUTHENTICATION ANAYLSIS")

    print("\n########## IP ADDRESS DATA BREAKDOWN ###########")

    try:
        if not data:
            print("AUTHENTICATION.LOG DATA IS NOT AVAILABLE") 
            return

    
        print("\n LOGIN: SUCCESS - FAILURE - ACC LOCKOUT ")

        success_count=0
        failed_count=0
        lockout_count=0 

        try:
            for line in data:
                if "LOGIN_SUCCESS" in line:
                    success_count = success_count + 1
                elif "LOGIN_FAILED" in line:
                    failed_count = failed_count + 1
                elif "ACCOUNT_LOCKED" in line:
                    lockout_count = lockout_count + 1
                else:
                    pass

            print (f"\nNUMBER OF SUCCESFUL LOGINS {success_count}")
            print (f"\nNUMBER OF FAILED LOGINS {failed_count}")
            print (f"\nNUMBER OF ACCOUNT LOCKOUTS {lockout_count}")

        except Exception as e:
            print("UNEXPECTED ERROR HAS OCCURED", e)


    ############ MOST OCCURING IPs WITH FAILED LOGINS ################

        print("\n MOST OCCURING IPs WITH FAILED LOGINS")


        failed_ip_count={}
        failed_ip_pattern =r"(\d{1,3}(?:\.\d{1,3}){3})"

        for line in data:
            match = re.search(failed_ip_pattern, line)
            if match:
                failed=match.group(0)

                if "LOGIN_FAILED" in line:
                    if failed not in failed_ip_count:
                        failed_ip_count[failed]=0
                    failed_ip_count[failed]+=1

        most_occuring_failed_ips=[]

        if failed_ip_count:
            most_occuring_failed_ips=sorted(failed_ip_count, key=failed_ip_count.get, reverse=True)[:5]

            for failed in most_occuring_failed_ips:
                print(f"\n FAILED LOGIN IP: {failed} \n ATTEMPTS MADE: ({failed_ip_count[failed]})")


    ################ MOST TARGETED USERNAMES #################

    
        print("\n MOST TARGETED USERNAMES FROM FAILED_LOGINS")

        username_count={}
        username_pattern=r"user=(\w+)"

        for line in data:
            if "LOGIN_FAILED" in line:
                match= re.search(username_pattern, line)
                if match:
                    username=match.group(1)

                    if username not in username_count:
                        username_count[username]=0
                    username_count[username]+=1

        most_tartgeted_usernames=[]

        if username_count:
            most_tartgeted_usernames=sorted(username_count, key=username_count.get, reverse=True)[:5]

            for username in most_tartgeted_usernames:
                print(f"\n TARGETED USERNAME: {username} \n OCCURED ({username_count[username]}) TIMES")

        

        print("\n################ SUSPICIOUS IP ADDRESS BREAKDOWN ##############")

        suspicious_ips=load_suspicious_ips() 

        print("\n ALERT : AUTHENTICATION.LOG HAS MATCHES TO SUSPICIOUS_IPS.TXT")

        matched_ip_port_data=[]

        for ip in failed_ip_count:
            if ip in suspicious_ips:
                matched_ip_port_data.append(ip)  

        if matched_ip_port_data:
            for sus_ip in matched_ip_port_data:
                print(f"\nIP ADDRESS: {sus_ip} - \n APPEARS {failed_ip_count[sus_ip]} TIMES ")
        else:
            print("NO MATCHES TO SUSPICIOUS_IPS.TXT HAVE BEEN FOUND")

        ########## RETURNING RESULTS ##########
        return{
            "SUCCESSFUL LOGINS": success_count,
            "FAILED LOGINS": failed_count,
            "ACCOUNT LOCKOUTS": lockout_count,
            "MOST FAILED LOGIN IPs": {ip: failed_ip_count[ip] for ip in most_occuring_failed_ips},
            "MOST TARGETED USERNAMES":{username: username_count[username] for username in most_tartgeted_usernames},
            "SUSPICIOUS MATCHES": {ip:failed_ip_count[ip] for ip in matched_ip_port_data}
        }


    except Exception as e:
        print ("UNEXPECTED ERROR HAS OCCURED", e)

def generate_report (firewall_results, authentication_results, filename="final_report.txt"):
    try:
        with open(filename,"w") as file:
            file.write("\n################ FINAL INVESTIGATION REPORT ##################\n")
            
            file.write("\n FIREWALL DATA ANALYSIS\n")
            
            if firewall_results:
                file.write(f"\nALLOWED CONNECTIONS: {firewall_results['ALLOWED COUNT']}")
                file.write("\n===========================================================\n")
                file.write(f"\nBLOCKED CONNECTIONS: {firewall_results['BLOCKED COUNT']}")
                file.write("\n===========================================================\n")
                file.write(f"\nMALFORMED LINES: {firewall_results['MALFORMED COUNT']}")
                file.write("\n===========================================================\n")
                file.write(f"\nUNIQUE BLOCKED IPs: {firewall_results['UNIQUE IPs']}")

                file.write("\n===========================================================\n")

                file.write(f"\nMOST OCCURING BLOCKED IPs:\n ")
                for ip, count in firewall_results['MOST OCCURING BLOCKED IPs'].items(): 
                    file.write(f" {ip} - OCCURED ({count}) TIMES\n")

                file.write("\n===========================================================\n")

                file.write(f"\nMOST TARGETED PORTS:\n")
                for port, count in firewall_results['MOST TARGETED PORTS'].items():
                        file.write(f" Port {port} TARGETED ({count}) TIMES \n")

                file.write("\n===========================================================\n")

                file.write("\n THE FOLLOWING SUSPICIOUS IPs APPREARED IN FIREWALL.LOG\n")
                for ip, count in firewall_results['SUSPICIOUS MATCHES'].items():
                    file.write(f" {ip} - OCCURED ({count}) TIMES \n")

            else:
                file.write("\nUNABLE TO RETRIEVE FIREWALL LOG DATA\n")

            file.write("\n###################################################################\n")

            file.write("\nAUTHENTICATION DATA ANALYSIS\n")

            if authentication_results:
                file.write(f"\nSUCCESSFUL LOGINS: {authentication_results['SUCCESSFUL LOGINS']}\n")
                file.write("\n===========================================================\n")
                file.write(f"\nFAILED LOGINS: {authentication_results['FAILED LOGINS']}\n")
                file.write("\n===========================================================\n")
                file.write(f"\nACCOUNT LOCKOUTS: {authentication_results['ACCOUNT LOCKOUTS']}\n")
                file.write("\n===========================================================\n")

                file.write(f"\nMOST FAILED LOGIN IPs:\n")
                for ip, count in authentication_results['MOST FAILED LOGIN IPs'].items():
                    file.write(f" {ip} - OCCURED ({count}) TIMES \n")

                file.write("\n===========================================================\n")

                file.write(f"\nMOST TARGETED USERNAMES:\n")
                for username, count in authentication_results['MOST TARGETED USERNAMES'].items():
                    file.write(f" {username}  - OCCURED ({count}) TIMES\n")

                file.write("\n===========================================================")

                file.write("\n THE FOLLOING USPICIOUS IPs APPREARED IN AUTHENTICATION.LOG\n")

                file.write(f"\nSUSPICIOUS MATCHES:\n")
                for ip, count in authentication_results['SUSPICIOUS MATCHES'].items():
                    file.write(f" {ip} - OCCURED  ({count}) TIMES \n")

            else:
                file.write("\nUNABLE TO RETRIEVE AUTHENTICATION LOG DATA")

        print(f" FINAL INVESTIGATION REPORT HAS BEEN SAVED TO '{filename}' SUCCESSFULLY")

    except IOError as e:
        print(" UNABLE TO WRITE THE REPORT THE FILE", e )

    except Exception as e:
        print(" UNEXPECTED ERROR HAS OCCURED", e)

def main():

    firewall_data=load_data("firewall.log")
    authentication_data=load_data("authentication.log")    

    firewall_results=None
    authentication_results=None

    menu=True

    while menu==True:

        print("\n========================================\n")
        print("\n          LOG ANALYSIS MENU              \n")
        print("\n========================================\n")
        print("\n WELCOME: PLEASE SELECT FROM THE FOLLOWING OPTIONS\n")
   
        print("""
        MENU\n
        1.FIREWALL.LOG ANALYSIS
        2.AUTHENTICATION.LOG ANALYSIS
        3.RUN FULL ANAYLSIS 
        4.GENERATE REPORT
        5.EXIT THE MENU""")

        option= input(("\nEnter an option..."))

        if option=='1':
            firewall_results=analyse_firewall_data(firewall_data)

        elif option=='2':
            authentication_results=analyse_authentication_data(authentication_data)

        elif option=='3':
            firewall_results=analyse_firewall_data(firewall_data)
            authentication_results=analyse_authentication_data(authentication_data)


        elif option == '4' :
                if not firewall_results:
                    firewall_results = analyse_firewall_data(firewall_data)
                if not authentication_results:
                    authentication_results = analyse_authentication_data(authentication_data)
                generate_report(firewall_results,authentication_results,filename="final_report.txt")

        elif option=='5':
            print("EXITING MENU....")
            break

        else:
            print("PLEASE PICK A NUMBER BETWEEN 1 - 4")

if __name__ == "__main__":
    main()


