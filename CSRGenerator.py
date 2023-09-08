from OpenSSL import crypto
import PySimpleGUI as sg
from os import _exit, path


# Variable
TYPE_RSA = crypto.TYPE_RSA

certificate_obj_name = {}
privatelKeypass =""
fileextn = ""
country = ""
Province =""
City=""
Organization = ""
OrganizationUnit = ""

# Generate pkey
def generateKey(type, bits, filename, secret):
    keyfile = f'{filename}.key'
    key = crypto.PKey()
    key.generate_key(type, bits)

    if path.exists(keyfile):
        print(keyfile, "Error: Certificate Key file exists.")
        print(" ")
    else:
        f = open(keyfile, "wb")
        encrypted_key = crypto.dump_privatekey(
            crypto.FILETYPE_PEM, key, "aes256", str.encode(secret) 
        )
        f.write(encrypted_key)
        f.close()
        print(f"Private Key Generated: {keyfile}")
    return key

# Generate CSR
def generateCSR(nodename, key, fileextn, Organization, OrganizationUnit, country, Province, City):
    csrfile = f'{nodename}.{fileextn}'
    req = crypto.X509Req()

    # Return an X509Name object representing the subject of the certificate.
    req.get_subject().CN = nodename
    req.get_subject().countryName = country
    req.get_subject().stateOrProvinceName = Province
    req.get_subject().localityName = City
    req.get_subject().organizationName = Organization
    req.get_subject().organizationalUnitName = OrganizationUnit
   
    # Set the public key of the certificate to pkey.
    req.set_pubkey(key)

    # Sign the certificate, using the key pkey and the message digest algorithm identified by the string digest.
    req.sign(key, "sha256")

    if path.exists(csrfile):
       print(csrfile, "Error: Certificate Key file exists.")
    else:
        f = open(csrfile, "wb")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        f.close()
        print(f"CSR Generated: {csrfile}")


# Layouts

generate_layout =[
    [
        sg.Button("Generate", size=(17,1), enable_events=True, key="-GENERATE-"),
        sg.Button("Close", size=(17,1)),
    ]
]

input_Data_tab_csr = [
    [sg.Text("CSR File Extension"), sg.Push(),sg.Listbox(['pem', 'csr'], default_values=['pem'], size=(25,2), enable_events=True,  no_scrollbar=True, key='-FILEXTN-')],
    [sg.Text("Private Key Password"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-KEYPASS-')],
    [sg.Text("Organization Name"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-ORGNAME-')],
    [sg.Text("Organization Unit"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-ORGUNIT-')],
    [sg.Text("Country"), sg.Push(),sg.Input(size=(25,1), default_text='CA', enable_events=True, key='-COUNTRY-')],
    [sg.Text("Province"), sg.Push(),sg.Input(size=(25,1), default_text='Ontario', enable_events=True, key='-PROVINCE-')],
    [sg.Text("City"), sg.Push(),sg.Input(size=(25,1), default_text='Toronto', enable_events=True, key='-CITY-')],
]

input_Cer_tab_csr = [
    [sg.Text("Certificate Name1"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-CERTNAME1-')],
    [sg.Text("Certificate Name2"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-CERTNAME2-')],
    [sg.Text("Certificate Name3"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-CERTNAME3-')],
    [sg.Text("Certificate Name4"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-CERTNAME4-')],
    [sg.Text("Certificate Name5"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-CERTNAME5-')],
    [sg.Text("Certificate Name6"), sg.Push(),sg.Input(size=(25,1), enable_events=True, key='-CERTNAME6-')],
]

logging_layout = [[sg.Text("CSR Generation Progress:")],
                  [sg.Multiline(size=(95,25), font='Courier 8', expand_x=True, expand_y=True, write_only=True,
                               reroute_stdout=True, reroute_stderr=True, echo_stdout_stderr=True, autoscroll=True, auto_refresh=True)]
                  ]

layout = [
    [   
        [sg.Frame('Generate CSR:',generate_layout)], 
        [sg.Frame('CSR Data:',[[sg.Column(input_Data_tab_csr), sg.Column(input_Cer_tab_csr)]])],
        sg.Column(logging_layout),
    ]
]

window = sg.Window("CSR Creator", layout)

# Reading Events from Window

while True:
    try:
        event, values = window.read()
        fileextn = values["-FILEXTN-"][0]
        privatelKeypass = values["-KEYPASS-"]
        Organization = values["-ORGNAME-"]
        OrganizationUnit =  values["-ORGUNIT-"]
        country =  values["-COUNTRY-"]
        Province =  values["-PROVINCE-"]
        City =  values["-CITY-"]
        certificate_obj_name['CERTNAME1'] = values["-CERTNAME1-"]
        certificate_obj_name['CERTNAME2']  = values["-CERTNAME2-"]
        certificate_obj_name['CERTNAME3']  = values["-CERTNAME3-"]
        certificate_obj_name['CERTNAME4']  = values["-CERTNAME4-"]
        certificate_obj_name['CERTNAME5']  = values["-CERTNAME5-"]
        certificate_obj_name['CERTNAME6']  = values["-CERTNAME6-"]

    except (ValueError, RuntimeError, TypeError, NameError):
            pass


    if event == "-GENERATE-":
        try:
            for key, value in certificate_obj_name.items():
                if value:
                    # Call key & CSR functions
                    key = generateKey(TYPE_RSA, 2048, value, privatelKeypass)
                    generateCSR(value, key, fileextn, Organization, OrganizationUnit, country, Province, City)

        except (ValueError, RuntimeError, TypeError, NameError):
            pass

    #Window Close event
    if event == "Close" or event =="Exit" or event == sg.WIN_CLOSED:
        window.close()
        _exit(0) 
