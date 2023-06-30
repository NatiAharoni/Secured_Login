import json
import re

def get_common_passwords():
    #from Wikipedia: https://en.wikipedia.org/wiki/Wikipedia:10,000_most_common_passwords
    common_passwords = []
    try:
        with open(r'C:\Users\liel\Desktop\Communication_LTD_computer_security\\200_common_passwords_wikipedia.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                common_passwords.append(line.strip())
    except:
        print("Can't read common passwrods file!")
    return common_passwords

def read_configuration():
    #In the configuation file (config.json): 
    # 'passwordMinLength' - minimum password length 
    # 'passwordHistory'  - how many passwords backwards to check, so the user doesn't use in a used password (MAX 3, beacuse of DB limit)
    # 'loginAttemptsAllowed': - how many fail login attempts are allowed
    # 'CheckCommonValues' - wether to check common passwords, 1 for check, 0 to not check
    # 'enableSqli' - wether to allow use in SQLI, 1 for allow, 0 to not allow
    # 'enableXSS'  wether to allow use in XSS, 1 for allow, 0 to not allow
    # 'mustToHaveChars' - what speacial chars must be in password
    data = {}
    try:
        with open(r"C:\Users\liel\Desktop\Communication_LTD_computer_security\config.json", 'r') as json_file:
            data = json.load(json_file)
            return data
    except:
        print("Can't read config file!")
    return data

