#  mini ioc checker - user input mode


# check if looks like ip
def is_ip(value):
    return value.replace(".", "").isdigit()

#  check private ip
def is_private(ip):
    
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        second = int(ip.split("."),[1])
        if 16 <= second <= 31:
            return True

    return False

# main tool function

def main():

    print("\n===IOC CHECKER ===\n")

    # user input
    ioc = input("Enter IOC: ")

    if is_ip(ioc):

        if is_private(ioc):
            print(ioc, "-->> PRIVATE -->> LOW")
        else:
            print(ioc, "-->> PUBLIC -->> MEDIUM")
    
    else:
        print(ioc, "-->> DOMAIN -->> HIGH")


main()

