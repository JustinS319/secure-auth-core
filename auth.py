# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2025 Justin Somerville
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import json
import sys
import os
import time
import smtplib
import re
import random
import string
import threading
from email.message import EmailMessage
from hashlib import pbkdf2_hmac
from getpass import getpass
from datetime import datetime
CONFIG = {
    "db_path": os.path.expanduser(os.path.join(os.path.dirname(__file__), "userAccounts.json")),
    "audit_log": os.path.expanduser(os.path.join(os.path.dirname(__file__), "auth_audit.log")),
    "email_config": os.path.expanduser(os.path.join(os.path.dirname(__file__), "config.json")),
    "max_failed": 5,
    "lockout_minutes": 15
}
def log(event: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(CONFIG["audit_log"], "a") as f:
        f.write(f"[{timestamp}] {event}\n")
def load_email_config():
    # Load email configuration from a JSON file.
    # Returns a dictionary with email settings. Used in email sending functions.
    file_path = CONFIG["email_config"]
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print("Config file not found!")
        return None
# Setting a global variable for email config to avoid reloading multiple times
email_cfg = load_email_config()
def load_accounts():
    filePath = CONFIG["db_path"]
    if not os.path.exists(filePath):
        with open(filePath, 'w') as file:
            json.dump({}, file)
    with open(filePath, "r") as file:
        return json.load(file)
def save_accounts(data):
    filePath = CONFIG["db_path"]
    with open(filePath, "w") as file:
        json.dump(data, file, indent=4)
def main():
    # Entry point of the program. Upon start-up it will automatically begin with this module.
    log("Program started")
    try:
        while True:
            # We are utilizing while True to ensure the program remains running. With it if we return we can run the same thing again otherwise;
            # in the case of returns or error handling the program would just end naturally right there.
            userChoice = input("Would you like to login or create an account (Login/Create/Exit/Forgot Password)?\n").lower()
            # Here we utilize .lower() to ensure we can easily check the contents of input insead of trying to account for any kind of case sensitivity.
            # "Create" != "create" but "Create".lower() == "create"
            if userChoice == "create":
                createAccount()
                # We could utilize the same try/except as below, but here we just hand of to createAccount() which utilizes return functions that
                # will just return us here if the same parameters are met.
            elif userChoice == "login":
                try:
                    login()
                    # We are going to attempt running the login function.
                except ValueError as E:
                    # If a specific parameter is met an error is raised this will catch that error. Without the catch the program will stop entirely.
                    print(E)
            elif userChoice == "exit":
                log("Program exited gracefully")
                print("Goodbye!")
                sys.exit(0)
                # sys.exit(0) here is used to shut-down the program safely. Passing a 0 signifies it is an expaected and wanted shut-down.
            elif userChoice == "forgot password":
                passwordReset()
            else:
                print("Invalid option. Please try again.")
    except KeyboardInterrupt:
        log("Program terminated by user (Ctrl+C)")
        print("\nShutting down...")
        time.sleep(1)
        print("Goodbye!")
        sys.exit(0)
def email(to_email,user = None,messageFrom = None):
    # Sends an email with a verification code to the specified email address.
    # We can also incorporate sms-gateways here if we want to send codes via text message.
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6)) # Generate a random 6-character code
    config = load_email_config()
    if config is None:
        raise FileNotFoundError("Config file missing!")
    from_email = config["email_address"]
    password = config["email_password"]
    msg = EmailMessage()
    msg['From'] = f"UserManagement <{from_email}>"
    msg['To'] = to_email
    msg['Subject'] = "Password Reset"
    if messageFrom is None:
        msg.set_content("Your verification code is: " + code)
        msg.add_alternative (f"""
        <html>
      <body>
        <h1 style="color: navy; font-family: Arial;">Hello, {user}!</h1>
        <p style="font-size: 14px;">Your verification code is <strong style="color: red;">{code}</strong></p>
      </body>
    </html>
    """, subtype='html')
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(from_email, password)
                smtp.send_message(msg)
            log(f"Password reset code sent to {to_email}")
            return code
        except smtplib.SMTPException as e:
            print("Error: Could not send email. Please check your internet connection and email credentials.")
            log(f"Failed to send email to {to_email}: {e}")
            return None
    # Also we are passing messageFrom to allow for possible future expansion where we might want to send different types of emails.
    # Such as internal notifications or alerts. For now it is only used for password resets.
def login():
    accounts = load_accounts()
    usernameAttempts = 0
    while usernameAttempts < 2:
        userName=input("Please enter your username:\n").lower()
        if userName in accounts:
            user_data = accounts[userName]
            now = time.time()
            # Brute-force protection
            if user_data.get("locked_until", 0) > now:
                print(f"Account locked. Try again in {int(user_data['locked_until'] - now)} seconds.")
                return
            if user_data.get("failed_attempts", 0) >= CONFIG["max_failed"]:
                user_data["locked_until"] = now + (CONFIG["lockout_minutes"] * 60)
                save_accounts(accounts)
                print(f"Too many failed attempts. Account locked for {CONFIG['lockout_minutes']} minutes.")
                log(f"Account {userName} locked due to brute force")
                return
            salt = user_data["salt"]
            accountHash = user_data["hash"]
            password = confirmPassword()
            if password != None:
                hashedPassword, _ = hashing(password, salt)
                if hashedPassword == accountHash:
                    user_data["failed_attempts"] = 0
                    save_accounts(accounts)
                    log(f"Successful login: {userName}")
                    dashboard(userName)
                    break
                else:
                    user_data["failed_attempts"] = user_data.get("failed_attempts", 0) + 1
                    save_accounts(accounts)
                    log(f"Failed login on {userName} — attempt {user_data['failed_attempts']}")
                    raise ValueError("Password did not match account — security exit")
            elif password == None:
                print("Returning to Main Menu!")
                return
        elif userName not in accounts:
            print("Username not found. Please try again.")
            usernameAttempts += 1
def createAccount(auth = None):
    if auth is not None:
        oops = input("Are you sure you want to create a new account? \n ").lower()
        if oops == "no":
            return
        elif oops != "yes":
            print("Input not recognized. Please type 'yes' or 'no'.")
            return
    accounts = load_accounts()
    attempts = 0
    while attempts < 3:
        userName = input("To create a new account please enter your username:\n").lower()
        if userName in accounts:
            print("Username already exists. Please try again.")
            attempts += 1
        else:
            break
    else:
        print("Too many failed attempts. Returning to main menu.")
        return
    # Normal user authLevel = 1
    # Admin authLevel       = 3
    # Master authLevel      = 5
    # First a master account created will be master by default.
    if len(accounts) == 0:
        authLevel = 5
    elif auth is None:
        authLevel = 1
    else:
        authLevel = auth
    print(f"The username you've chosen is: " + userName.capitalize())
    password = confirmPassword()
    if password is None:
        return
    else:
        emailAttempts = 0
        while emailAttempts < 3:
            email = input("Please provide your email address for password resets:\t")
            regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            match = re.fullmatch(regex, email)
            if match:
                print(f"valid email")
                break
            else:
                print("invalid email.")
                emailAttempts += 1
        else:
            print("Too many invalid attempts. Returning to main menu.")
            return
        hashPass,salted = hashing(password)
        accounts[userName] = {
            "salt":salted,
            "hash": hashPass,
            "auth": authLevel,
            "email": email,
            "failed_attempts": 0,
            "locked_until": 0
        }
        save_accounts(accounts)
        log(f"Account created: {userName} (auth={authLevel})")
        print("Thank you for creating an account!")
        if auth == None:
            dashboard(userName)
        else:
            return
def hashing(password, salt=None, iterations = 300_000):
    if salt is None:
        salt = os.urandom(16)

    else:
        salt = bytes.fromhex(salt) if isinstance(salt, str) else salt
    hash_val = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return hash_val.hex(), salt.hex()
def dashboard(user):
    accounts = load_accounts()
    userPanel = ("reset password", "email")
    adminPanel = {"delete user", "reset password", "email"}
    masterPanel = {"set admin","delete user", "transfer master", "reset password", "email"}
    while True:
        print(f"welcome to the user dashboard {user}")
        accountStats()
        if accounts[user]["auth"] == 5:
            for item in masterPanel:
                print(f"-{item} ")
        elif accounts[user]["auth"] == 3:
            for item in adminPanel:
                print(f"-{item} ")
        else:
            for item in userPanel:
                print(f"-{item} ")
        dashboardChoice = input("Current features are in progress but please choose from what we have currently.\n").lower()
        if dashboardChoice == "delete":
            deleteUser(user)
        elif dashboardChoice == "set admin":
            setAdmin(user)
        elif dashboardChoice == "master":
            transferMaster(user)
        elif dashboardChoice == "reset password":
            passwordReset(user, from_dashboard=True)
        #elif dashboardChoice == "email":
        #    userEmail(user)
        elif dashboardChoice == "logout":
            log(f"User {user} logged out")
            return
def confirmPassword(max_attempts=3):
    for attempt in range(max_attempts):
        p1 = getpass("Password: ")
        p2 = getpass("Confirm password: ")
        if p1 == p2:
            return p1
        print(f"Passwords didn’t match. Attempts remaining: {max_attempts - attempt - 1}")
    print("Too many failed attempts.")
    return None
def deleteUser(userName):
    accounts = load_accounts()
    if accounts[userName]["auth"] > 2:
        for u in accounts:
            print(f"- {u} (auth: {accounts[u]['auth']})")
        targetAccount = input("Please select the user you would like to delete\n")
        if targetAccount == "exit":
            return
        if targetAccount not in accounts:
            print("Sorry no matching accounts.")
            return
        if accounts[targetAccount]["auth"] > 4:
            print("Can not delete the Master account.")
            return
        if targetAccount == userName:
            yesNo = input("Are you sure you would like to delete your own account?\n").lower()
            if yesNo == "no":
                return
        maybe = input(f"Are you sure you would like to delete {targetAccount}?\n").lower()
        if maybe != "yes":
            return
        del accounts[targetAccount]
        save_accounts(accounts)
        log(f"User {targetAccount} deleted by {userName}")
def setAdmin(user):
    accounts = load_accounts()
    if accounts[user]["auth"] != 5:
        print("Sorry you can not access this feature.")
        return
    choice = input(f" Welcome Master {user}. Are we creating a new admin or elevating an existing account? \n ''Create/ Elevate''\n").lower()
    if choice == "create":
        createAccount(auth = 3)
    elif choice == "elevate":
        print("Here's a list of current users.")
        for u in accounts:
            print(f"- {u} (auth: {accounts[u]['auth']})")
        accountName = input("Please select an account to elevate.\n")
        if accountName not in accounts:
            print("Sorry that user does not exist.")
            return
        yesNo = input(f"Are you sure you would like to elevate {accountName}?\n").lower()
        if yesNo == "yes":
            accounts[accountName]["auth"] = 3
            save_accounts(accounts)
            log(f"{accountName} elevated to Admin by {user}")
            print(f"{accountName} has been successfully elevated to Admin.")
        else:
            print("Operation cancelled.")
            return
    else:
        return
def transferMaster(user):
    accounts = load_accounts()
    while True:
        if accounts[user]["auth"] < 5:
            print("Access Denied!")
            time.sleep(5)
            return
        userSure = input("Are you sure you want to transfer master?").lower()
        if userSure != "yes":
            return
        for u in accounts:
            print(f"- {u} (auth: {accounts[u]['auth']})")
        targetAccount = input("Please select the user you would like to promote to master....\n")
        if targetAccount not in accounts:
            print("Sorry no matching accounts.")
            return
        maybe = input(f"Are you sure you would like to elevate {targetAccount} to master?\n Rememeber this is irreversible.\n").lower()
        if maybe != "yes":
            return
        accounts[targetAccount]['auth'] = 5
        accounts[user]['auth'] = 3
        save_accounts(accounts)
        log(f"Master transferred from {user} to {targetAccount}")
        print(f"Process complete {targetAccount} has succesfully been elevated to Master. \n Returning to dashboard...........")
        time.sleep(3)
        return
def verify_code_with_timeout(code, timeout_seconds=300):
    expired = threading.Event()
    def timer():
        time.sleep(timeout_seconds)
        expired.set()
    threading.Thread(target=timer, daemon=True).start()
    seconds = timeout_seconds % 60
    print(f"Please enter the code you were sent (expires in {timeout_seconds//60} minutes and {seconds} seconds):")
    while not expired.is_set():
        usrentry = input("> ")
        if usrentry == code:
            return True
        print("Incorrect code. Try again.")
    print("Code expired.")
    return False
def passwordReset(user =None, from_dashboard=False):
    accounts = load_accounts()
    if user is None:
        user = input("Please enter your username.\t")
        if user not in accounts:
            print("Sorry username doesn't exist.")
            log(f"Password reset failed: unknown user '{user}'")
            return
    Useremail = accounts[user]["email"]
    def newPassword():
        newPass=confirmPassword()
        hash, salt = hashing(newPass)
        accounts[user]["hash"] = hash
        accounts[user]["salt"] = salt
        accounts[user]["failed_attempts"] = 0
        accounts[user]["locked_until"] = 0
        save_accounts(accounts)
        log(f"Password reset successful for {user}")
    if not from_dashboard:
        try:
            code = email(Useremail, user = user)   # send & return code
        except FileNotFoundError:
            return
        if not verify_code_with_timeout(code, timeout_seconds=300):
            return
        newPassword()
        print("Password changed successfully!")
    else:
        salt = accounts[user]["salt"]
        accountHash = accounts[user]["hash"]
        print("Please verify your password.")
        password = confirmPassword()
        if not password:
            print("Password verification cancelled.")
            return
        hashedPassword, _ = hashing(password, salt)
        if hashedPassword == accountHash:
            newPassword()
            print("Password changed successfully!")
        else:
            print("Password verification failed.")
            log(f"Dashboard password reset failed for {user}")
def accountStats():
    accounts = load_accounts()
    total = len(accounts)
    admins = sum(1 for u in accounts if accounts[u]['auth'] == 3)
    masters = sum(1 for u in accounts if accounts[u]['auth'] == 5)
    users = total - admins - masters
    print(f"Users: {users}, Admins: {admins}, Masters: {masters}, Total: {total}")
if __name__ == "__main__":
    main()