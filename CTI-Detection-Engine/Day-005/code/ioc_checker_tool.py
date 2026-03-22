#  mini ioc checker tool

#  check if ip format
def is_ip(value):
    return value.replace(".", "").isdigit()

#  check private ip range
def is_private(ip):

    if ip.startswith("10."):
        return True

    if ip.startswith("192.168."):
        return True

    if ip.startswith("172."):

        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            return True

    return False

# input validation
def valid_input(ioc):

    if len(ioc.strip()) == 0:
        return False

    return True

# classfy ioc
def classify(ioc):

    if is_ip(ioc):

        if is_private(ioc):
            return "PRIVATE", "LOW"

        else:
            return "PUBLIC", "MEDIUM"

    return "DOMAIN", "HIGH"

# Main Tool
def main():

    print("\n=== IOC CHECKER TOOL ===")

    ioc = input("\nEnter IOC: ").strip()

    if not valid_input(ioc):
        print("Invalid input")
        return

    ioc_type, risk = classify(ioc)

    print("\nResult:")
    print(f"IOC : {ioc}")
    print(f"Type : {ioc_type}")
    print(f"Risk : {risk}")

main()
