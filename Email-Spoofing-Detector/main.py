import re
from emailSpoofDetection import emailSpoofDetection

def parse_eml_header(eml_file):
    with open(eml_file, 'r', encoding='utf-8') as f:
        header = ''
        for line in f:
            if line == '\n':
                break
            header += line
    return header

if __name__ == "__main__":
    eml_file = input("Enter the path to the .eml file: ")
    header = parse_eml_header(eml_file)
    emailDomain = input("Enter the email domain to validate against: ")
    result = emailSpoofDetection(header, emailDomain)
    print(result)

