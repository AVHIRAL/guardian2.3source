from PyQt5.QtCore import Qt
from PyQt5.QtCore import QThread
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QLabel
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QThread, QTimer, QCoreApplication
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import QDialog, QCheckBox, QVBoxLayout, QPushButton
from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal, QCoreApplication, pyqtSlot
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QLabel, QWidget, QPushButton, QFrame)
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QSystemTrayIcon, QAction, QMenu
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QDialog, QVBoxLayout
from PyQt5.QtWidgets import QMainWindow, QApplication, QTableWidget, QTableWidgetItem
from PyQt5.QtWidgets import QApplication, QMessageBox, QMainWindow, QAction, QSystemTrayIcon, QMenu
from PyQt5.QtWidgets import QMainWindow, QTableWidget, QTableWidgetItem, QPushButton, QApplication
from PyQt5.QtWidgets import QMainWindow, QTableWidget, QTableWidgetItem, QPushButton, QApplication, QMessageBox
from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QGridLayout, QWidget, QAction, QSystemTrayIcon, QMenu
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
from PyQt5.QtWidgets import QMainWindow, QTableWidget, QTableWidgetItem, QPushButton, QMessageBox, QApplication
from PyQt5.QtWidgets import QApplication, QMainWindow, QSystemTrayIcon, QMenu, QAction, QTextEdit, QVBoxLayout, QWidget, QLabel, QPushButton
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QAction, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QTextEdit, QLabel, QPushButton
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QPushButton, QVBoxLayout, QWidget, QMessageBox, QSystemTrayIcon, QAction, QMenu
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QPushButton, QVBoxLayout, QWidget, QAction, QSystemTrayIcon, QMenu
from PyQt5.QtCore import Qt, QThread, QTimer, QCoreApplication, pyqtSignal
from PyQt5.QtWidgets import (QApplication, QMainWindow, QSystemTrayIcon, QMenu, QAction,
                             QTextEdit, QVBoxLayout, QHBoxLayout, QWidget, QLabel,
                             QPushButton, QTableWidget, QTableWidgetItem)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QAction
from pynput.keyboard import Key, Listener
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtCore import QCoreApplication
from PyQt5.QtCore import QTimer, QCoreApplication
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import QFileDialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet
from pynput import keyboard
from PyQt5.QtCore import QEvent
from random import shuffle
from PIL import Image, ImageTk
import tkinter as tk
import subprocess
import threading
import webbrowser
import pyautogui
import psutil
import hashlib
import winreg
import datetime
import time
import sys
import os
import json
import shutil
import winshell
import win32com.client 
import configparser
import base64

def centre_fenetre(fenetre):
    # pour centrer la fenêtre à l'écran
    fenetre.update_idletasks()
    largeur = fenetre.winfo_width()
    hauteur = fenetre.winfo_height()
    x = (fenetre.winfo_screenwidth() // 2) - (largeur // 2)
    y = (fenetre.winfo_screenheight() // 2) - (hauteur // 2)
    fenetre.geometry('{}x{}+{}+{}'.format(largeur, hauteur, x, y))

def afficher_image():
    fenetre = tk.Tk()
    fenetre.title('Start')
    fenetre.overrideredirect(1)

    image = Image.open('start.png')
    photo = ImageTk.PhotoImage(image)

    label = tk.Label(fenetre, image=photo)
    label.pack()

    centre_fenetre(fenetre)

    fenetre.after(5000, fenetre.destroy)
    fenetre.mainloop()

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, alert_signal):
        super().__init__()
        self.alert_signal = alert_signal
        self.file_activity = {}

    def on_modified(self, event):
        if not event.is_directory:
            process = self.get_process_by_path(event.src_path)
            if process:
                self.file_activity[process.pid] = self.file_activity.get(process.pid, 0) + 1
                if self.file_activity[process.pid] > 100:  
                    self.alert_signal.emit(f"Potentiel ransomware détecté: modification rapide des fichiers par {process.name()} (PID: {process.pid})")
                    self.take_action(process.pid)

    def get_process_by_path(self, path):
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            if proc.info['open_files']:
                for f in proc.info['open_files']:
                    if f.path == path:
                        return proc
        return None

    def take_action(self, pid):
        try:
            proc = psutil.Process(pid)
            proc.terminate()  
            self.alert_signal.emit(f"Processus suspect (PID: {pid}) terminé.")
        except Exception as e:
            self.alert_signal.emit(f"Erreur lors de la tentative de terminaison du processus (PID: {pid}): {str(e)}")

class RansomwareProtection(QThread):
    alertSignal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.observer = Observer()
        self.event_handler = RansomwareEventHandler(self.alertSignal)
        self.watch_directories = ['C:\\', 'D:\\']  # Directoires à surveiller

    def run(self):
        for directory in self.watch_directories:
            self.observer.schedule(self.event_handler, directory, recursive=True)
        self.observer.start()
        self.observer.join()

    def stop(self):
        self.observer.stop()
        self.observer.join()

class TrojanScanner(QThread):
    alertSignal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.active = True
        self.known_trojans_hashes = self.load_trojan_hashes()

    def run(self):
        while self.active:
            self.scan_for_trojans()
            self.sleep(60)  # Scanne toutes les minutes

    def load_trojan_hashes(self):
        trojan_hashes = {}
        try:
            with open('hash-list.csv', 'r', newline='', encoding='utf-8') as file:
                reader = csv.reader(file)
                for row in reader:
                    if len(row) >= 2:
                        hash_value, description = row
                        trojan_hashes[hash_value.strip()] = description.strip()
        except Exception as e:
            self.alertSignal.emit(f"Failed to load trojan hashes: {str(e)}")
        return trojan_hashes

    def scan_for_trojans(self):
        # Liste des chemins communs où les trojans pourraient être installés
        paths_to_watch = ['C:\\Windows\\', 'C:\\Program Files\\', f'C:\\Users\\{os.getlogin()}\\AppData\\']
        for path in paths_to_watch:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file.endswith('.exe') or file.endswith('.dll'):
                        file_hash = self.get_file_hash(file_path)
                        if file_hash in self.known_trojans_hashes:
                            description = self.known_trojans_hashes[file_hash]
                            self.alertSignal.emit(f"Trojan detected: {description} at {file_path}")
                            self.remove_trojan(file_path)

    def get_file_hash(self, file_path):
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                buffer = f.read(65536)
                while len(buffer) > 0:
                    hasher.update(buffer)
                    buffer = f.read(65536)
        except Exception as e:
            self.alertSignal.emit(f"Error reading file {file_path}: {str(e)}")
        return hasher.hexdigest()

    def remove_trojan(self, file_path):
        try:
            os.remove(file_path)
            self.alertSignal.emit(f"Trojan removed: {file_path}")
        except Exception as e:
            self.alertSignal.emit(f"Failed to remove trojan: {file_path}. Error: {str(e)}")

    def stop(self):
        self.active = False

def trouver_chemin_thunderbird():
    # Tente de trouver le chemin d'installation de Thunderbird sur un système Windows en cherchant dans des emplacements communs.
    chemins_possibles = [
        "C:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe",
        "H:\\Program Files\\Mozilla Thunderbird\\thunderbird.exe",
        "C:\\Program Files (x86)\\Mozilla Thunderbird\\thunderbird.exe"
    ]
    for chemin in chemins_possibles:
        if os.path.exists(chemin):
            return chemin
    return None

class ProtectionThunderbird(QThread):
    signal_alerte = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.chemin_thunderbird = trouver_chemin_thunderbird()
        self.dernier_hash = None
        self.intervalle_verification = 10000  

    def run(self):
        while True:
            self.surveiller_thunderbird()
            QThread.sleep(self.intervalle_verification // 1000)

    def surveiller_thunderbird(self):
        if not self.chemin_thunderbird:
            self.signal_alerte.emit("Installation de Thunderbird non trouvée.")
            return

        hash_actuel = self.calculer_hash_fichier(self.chemin_thunderbird)
        if self.dernier_hash is not None and self.dernier_hash != hash_actuel:
            self.signal_alerte.emit("Modification détectée dans l'exécutable de Thunderbird.")
        self.dernier_hash = hash_actuel

    def calculer_hash_fichier(self, chemin_fichier):
        hasher = hashlib.sha256()
        try:
            with open(chemin_fichier, 'rb') as f:
                contenu = f.read()
                hasher.update(contenu)
        except Exception as e:
            self.signal_alerte.emit(f"Échec de la lecture du fichier {chemin_fichier} : {str(e)}")
        return hasher.hexdigest()

class SurveillanceReseau(QThread):
    signal_activite_suspecte = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.seuil = 100  # Seuil exemple pour "trop de connexions"

    def run(self):
        while True:
            self.verifier_activite_reseau()
            QThread.sleep(10)  # Vérification toutes les 10 secondes

    def verifier_activite_reseau(self):
        compteur_ip = {}
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == "ESTABLISHED" and conn.raddr:
                ip = conn.raddr.ip
                compteur_ip[ip] = compteur_ip.get(ip, 0) + 1
                if compteur_ip[ip] > self.seuil:
                    self.signal_activite_suspecte.emit(f"Volume élevé de connexions détecté de l'IP : {ip}")

def bloquer_ip(adresse_ip):
    # Bloque une adresse IP en utilisant le pare-feu Windows
    cmd = f"netsh advfirewall firewall add rule name=\"Blocage {adresse_ip}\" dir=in action=block remoteip={adresse_ip} enable=yes"
    subprocess.run(cmd, shell=True)

def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("log.log", "a") as log_file:
        log_file.write(f"{timestamp} - {message}\n")

class PasswordEncryptor:
    def __init__(self):
        self.key = self.load_or_generate_key()

    def load_or_generate_key(self):
        key_path = "encryption.key"
        if os.path.exists(key_path):
            with open(key_path, "rb") as key_file:
                key = key_file.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, "wb") as key_file:
                key_file.write(key)
        return key

    def encrypt_password(self, password):
        f = Fernet(self.key)
        encrypted_password = f.encrypt(password.encode())
        return encrypted_password

    def decrypt_password(self, encrypted_password):
        f = Fernet(self.key)
        decrypted_password = f.decrypt(encrypted_password).decode()
        return decrypted_password

def detect_suspicious_processes():
    suspicious_behaviors = ['keylog', 'logger', 'spy']
    for process in psutil.process_iter(['name']):
        if any(behavior in process.info['name'].lower() for behavior in suspicious_behaviors):
            print(f"Suspicious process detected: {process.info['name']}")

class KeyEvent(QEvent):
    EventType = QEvent.Type(QEvent.registerEventType())

    def __init__(self, key, shift_pressed):
        super().__init__(KeyEvent.EventType)
        self.key = key
        self.shift_pressed = shift_pressed

class VirtualKeyboardWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AntiKeylogger Keyboard")
        self.setWindowIcon(QIcon("icon.png"))
        self.init_keys()
        self.initUI()
        self.start_keyboard_listener()
        self.shift_pressed = False

    def init_keys(self):
        # Initialisation et mélange des touches de manière sécurisée
        base_keys = [
            ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '&', 'é', '"', '^', '(', '-', 'è', '_', 'ç', 'à', ')', '='],
            ['a', 'z', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'q', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'w', 'x'],
            ['c', 'v', 'b', 'n', ',', ';', ':', '!', '@', '%', '*', 'ù', '$', '^', '¨', '+', '~', '#', '{', '}', '[', ']'],
            ['A', 'Z', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', 'Q', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'W', 'X'],
            ['C', 'V', 'B', 'N', '/', '\\', '<', '>', '?']
        ]
        self.keys = [list(row) for row in base_keys]
        for row in self.keys:
            shuffle(row)

    def initUI(self):
        self.buttons = []
        central_widget = QWidget(self)
        layout = QGridLayout(central_widget)
        for i, row in enumerate(self.keys):
            button_row = []
            for j, key in enumerate(row):
                button = QPushButton(key)
                button.setFont(QFont('Arial', 12))
                button.setFixedSize(40, 40)
                button.setStyleSheet("background-color: lightgray;")
                button.clicked.connect(lambda ch, btn=button: self.key_pressed(btn))
                layout.addWidget(button, i, j)
                button_row.append(button)
            self.buttons.append(button_row)
        self.setCentralWidget(central_widget)        
        self.show()

    def start_keyboard_listener(self):
        self.listener = Listener(on_press=self.on_press, on_release=self.on_release)
        self.listener.start()

    def on_press(self, key):
        if key == Key.shift:
            self.shift_pressed = True
        elif hasattr(key, 'char') and key.char:
            QApplication.postEvent(self, KeyEvent(key.char, self.shift_pressed))

    def on_release(self, key):
        if key == Key.shift:
            self.shift_pressed = False

    def event(self, event):
        if isinstance(event, KeyEvent):
            key_char = event.key
            shift_pressed = event.shift_pressed
            char_to_display = key_char.upper() if shift_pressed else key_char.lower()

            for row in self.buttons:
                for button in row:
                    if button.text() == char_to_display:
                        self.highlight_button(button)
            return True
        return super().event(event)

    def highlight_button(self, button):
        button.setStyleSheet("background-color: red;")
        QTimer.singleShot(100, lambda: self.reset_button_style(button))

    def key_pressed(self, button):
        button.setStyleSheet("background-color: navy; color: yellow; font-weight: bold;")
        pyautogui.press(button.text().lower())
        QTimer.singleShot(100, lambda: self.reset_button_style(button))
        self.highlight_button(button)

    def reset_button_style(self, button):
        button.setStyleSheet("background-color: lightgray; color: black;")

    def closeEvent(self, event):
        event.ignore()
        self.hide()

class SystemRestoreSecurity(QThread):
    def __init__(self, check_interval=3600, parent=None):
        super(SystemRestoreSecurity, self).__init__(parent)
        self.check_interval = check_interval  # Intervalle de vérification en secondes

    def run(self):
        while True:
            self.ensure_system_restore_enabled("C:")
            time.sleep(self.check_interval)  # Attendre avant de vérifier à nouveau

    def ensure_system_restore_enabled(self, drive):
        # Active la restauration du système pour le lecteur spécifié s'il est désactivé
        # Vérifie d'abord si la restauration est activée
        check_cmd = f"powershell -Command \"(Get-ComputerRestorePoint).count -gt 0\""
        result = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
        if "False" in result.stdout:
            print("La restauration du système est désactivée. Tentative de réactivation...")
            # Réactive la restauration du système
            enable_cmd = f"powershell -Command \"Enable-ComputerRestore -Drive '{drive}\\'\""
            subprocess.run(enable_cmd, shell=True)
            print(f"La restauration du système a été réactivée pour le lecteur {drive}.")
        else:
            print("La restauration du système est déjà activée.")

def save_config(key, value):
    config = configparser.ConfigParser()
    config.read('config.ini')
    if 'DEFAULT' not in config:
        config['DEFAULT'] = {}
    config['DEFAULT'][key] = str(value)
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

def load_config(key):
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config['DEFAULT'].get(key, 'False')

# Fonction pour détecter et logger les processus suspects
def detect_suspicious_processes():
    """
    Détecte les processus suspects en se basant sur des critères comportementaux
    plutôt que sur une simple correspondance de noms.
    """
    for proc in psutil.process_iter(attrs=['name', 'pid', 'connections', 'memory_percent', 'cpu_percent']):
        try:
            # Critère basé sur l'utilisation de la mémoire
            if proc.info['memory_percent'] > 50:
                log_event(f"Utilisation anormale de la mémoire détectée: {proc.info['name']} (PID: {proc.info['pid']})")

            # Critère basé sur l'utilisation du CPU
            if proc.info['cpu_percent'] > 80:
                log_event(f"Utilisation anormale du CPU détectée: {proc.info['name']} (PID: {proc.info['pid']})")

            # Critère basé sur les connexions réseau
            if proc.connections() and len(proc.connections()) > 100:
                log_event(f"Activité réseau anormale détectée: {proc.info['name']} (PID: {proc.info['pid']})")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Fonction pour surveiller l'activité réseau et détecter des comportements suspects
def monitor_network_activity(threshold=100):
    ip_counts = {}
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == "ESTABLISHED" and conn.raddr:
            ip = conn.raddr.ip
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            if ip_counts[ip] > threshold:
                log_event(f"Activité réseau suspecte détectée: {ip} a effectué plus de {threshold} connexions.")

        # Réinitialiser le compteur toutes les 10 secondes pour surveiller les pics d'activité
        time.sleep(10)
        ip_counts.clear()

class FirewallManager:
    def __init__(self):
        # Initialisation si nécessaire
        pass
    
    def block_ip(self, ip_address):
        """
        Bloque l'adresse IP spécifiée en ajoutant une règle de pare-feu.
        """
        rule_name = f"BlockIP_{ip_address.replace('.', '_')}"  # Nom de la règle
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name={}".format(rule_name),
            "dir=in", "action=block",
            "remoteip={}".format(ip_address),
            "enable=yes"
        ]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"L'adresse IP {ip_address} a été bloquée avec succès.")
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors du blocage de l'adresse IP {ip_address}: {e}")
    
    def unblock_ip(self, ip_address):
        """
        Débloque l'adresse IP spécifiée en supprimant la règle de pare-feu correspondante.
        """
        rule_name = f"BlockIP_{ip_address.replace('.', '_')}"  # Nom de la règle
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name={}".format(rule_name),
            "remoteip={}".format(ip_address)
        ]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"L'adresse IP {ip_address} a été débloquée avec succès.")
        except subprocess.CalledProcessError as e:
            print(f"Erreur lors du déblocage de l'adresse IP {ip_address}: {e}")

class App(QApplication):
    alertSignal = pyqtSignal(str)
    def __init__(self, sys_argv):
        super(App, self).__init__(sys_argv)
        self.setQuitOnLastWindowClosed(False)
        
        self.trayIcon = QSystemTrayIcon(QIcon("icon.png"), self)
        self.trayIcon.setToolTip("AVHIRAL-Guardian V2.3")
        self.trayIcon.show()
        
        # Initialisation des fenêtres ici
        self.logWindow = LogAttaquesWindow()
        self.infoWindow = InfosGuardianWindow()
        self.scanProcessWindow = ScanProcessWindow()
        self.iftopWindow = IFTOPWindow()
        self.firewallWindow = FirewallWindow()  
        self.scanProcessWindow = ScanProcessWindow(self.firewallWindow)
        self.iftopWindow = IFTOPWindow(self.firewallWindow)
        self.antiRootkitWindow = AntiRootkitWindow()
        self.alertSignal.connect(self.handle_alert)

        self.setupMenu()
        self.trayIcon.show()

    def handle_alert(self, message):
        # Vérifie si les notifications d'alerte sont activées avant d'afficher la fenêtre de log
        if load_config('alert_notifications') == 'True':
            self.logWindow.updateLogs(message)  # Mettre à jour les logs avec le nouveau message d'alerte
            self.logWindow.show()  # Affiche la fenêtre

    def setupMenu(self):
        menu = QMenu()
 
        # Log menu       
        logAttaquesAction = QAction("Log des Attaques", self)
        logAttaquesAction.triggered.connect(self.logWindow.show)
        menu.addAction(logAttaquesAction)
        self.trayIcon.setContextMenu(menu)

        # ScanProcess menu
        scanProcessAction = QAction("Scan Process", self)
        scanProcessAction.triggered.connect(self.scanProcessWindow.show)
        menu.addAction(scanProcessAction)
 
        # Firewall menu
        firewallAction = QAction("Firewall Manager", self)
        firewallAction.triggered.connect(self.firewallWindow.show)
        menu.addAction(firewallAction)

        # IFTOP menu
        iftopAction = QAction("IFTOP", self)
        iftopAction.triggered.connect(self.iftopWindow.show)
        menu.addAction(iftopAction)

         # AntiRootkit menu
        antiRootkitAction = QAction("AntiRootkit", self)
        antiRootkitAction.triggered.connect(self.showAntiRootkitWindow)
        menu.addAction(antiRootkitAction)  

        # Adding AntiKeylogger option
        antiKeyloggerAction = QAction("AntiKeylogger", self)
        antiKeyloggerAction.triggered.connect(self.open_keyboard_window) 
        menu.addAction(antiKeyloggerAction)

        # Infos menu
        infosGuardianAction = QAction("Infos Guardian", self)
        infosGuardianAction.triggered.connect(self.infoWindow.show)
        menu.addAction(infosGuardianAction)

        # Ooption démarrage
        startupOptionAction = QAction("Option Démarrage", self)
        startupOptionAction.triggered.connect(self.showStartupOptionWindow)
        menu.addAction(startupOptionAction)

        # Quitter menu
        quitAction = QAction("Quitter Guardian", self)
        quitAction.triggered.connect(self.quit)
        menu.addAction(quitAction)  

        self.trayIcon.setContextMenu(menu) 

    def open_keyboard_window(self):
        # Vérifie si l'instance de la fenêtre du clavier existe déjà et si elle est visible
        if hasattr(self, 'keyboard_window') and self.keyboard_window.isVisible():
            self.keyboard_window.activateWindow()  # Met la fenêtre existante au premier plan
        else:
            self.keyboard_window = VirtualKeyboardWindow()  # Crée une nouvelle instance
            self.keyboard_window.show()

    def showAntiRootkitWindow(self):
        self.antiRootkitWindow = AntiRootkitWindow()
        self.antiRootkitWindow.show()

    def showFirewallWindow(self):
        self.firewallWindow = FirewallWindow()
        self.firewallWindow.show()     

    def showLogAttaquesWindow(self):
        self.logWindow = LogAttaquesWindow()
        self.logWindow.show()

    def showInfosGuardianWindow(self):
        self.infoWindow = InfosGuardianWindow()
        self.infoWindow.show()

    def showStartupOptionWindow(self):
        self.startupOptionWindow = StartupOptionWindow()
        self.startupOptionWindow.show()

class StartupOptionWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Option Démarrage")
        self.setGeometry(100, 100, 300, 100)
        self.setWindowIcon(QIcon("icon.png"))
        layout = QVBoxLayout()

        self.startupCheckBox = QCheckBox("Ouvrir avec Windows")
        self.notificationCheckBox = QCheckBox("Activer les notifications d'alerte")
        layout.addWidget(self.startupCheckBox)
        layout.addWidget(self.notificationCheckBox)

        self.validateButton = QPushButton("Valider")
        self.validateButton.clicked.connect(self.apply_settings)  # Appel à apply_settings au clic
        layout.addWidget(self.validateButton)

        self.setLayout(layout)
        self.setFixedSize(self.size())
        
        # Charger les configurations existantes
        self.load_config()

    def apply_settings(self):
        self.set_startup()  # Applique le paramètre de démarrage
        save_config('alert_notifications', self.notificationCheckBox.isChecked())  # Sauvegarde le paramètre des notifications
        save_config('startup_with_windows', self.startupCheckBox.isChecked())  # Sauvegarde le paramètre de démarrage
        self.close()

    def set_startup(self):
        startup_folder = winshell.startup()
        shortcut_path = os.path.join(startup_folder, "AVHIRALGuardian_V2.3.lnk")
        target_exe = "AVHIRALGuardian_v2.3.exe"
        target_path = os.path.join(os.getcwd(), target_exe)

        if self.startupCheckBox.isChecked():
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = target_path
            shortcut.WorkingDirectory = os.getcwd()
            shortcut.IconLocation = target_path
            shortcut.save()
        else:
            try:
                os.remove(shortcut_path)
            except FileNotFoundError:
                QMessageBox.information(self, "Info", "Aucun raccourci existant à supprimer.")

    def load_config(self):
        # Cette méthode doit charger les configurations de 'startup_with_windows' et 'alert_notifications'
        self.startupCheckBox.setChecked(load_config('startup_with_windows') == 'True')
        self.notificationCheckBox.setChecked(load_config('alert_notifications') == 'True')

    def closeEvent(self, event):
        event.ignore()
        self.hide()

class ScanThread(QThread):
    signal = pyqtSignal(str)

    def run(self):
        # Vous devez ajuster le script_path à l'emplacement de votre script antirootkit
        script_path = "path_to_your_script.ps1"
        cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path]
        try:
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
            self.signal.emit(output)
        except subprocess.CalledProcessError as e:
            self.signal.emit(f"Erreur lors du scan: {e.output}")

class AntiRootkitWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AntiRootkit")
        self.setGeometry(100, 100, 700, 200)
        self.setWindowIcon(QIcon("icon.png"))
        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(['Détection', 'Chemin', 'Action'])
        self.setCentralWidget(self.tableWidget)
        self.startScan()

    def startScan(self):
        self.scanThread = ScanThread()
        self.scanThread.signal.connect(self.processScanResults)
        self.scanThread.start()

    @pyqtSlot(str)  # Use the pyqtSlot decorator for slots
    def processScanResults(self, output):
        # Ensure UI updates are done in the main thread
        QMetaObject.invokeMethod(self, "updateTable", Qt.QueuedConnection, Q_ARG(str, output))

    @pyqtSlot(str)
    def processScanResults(self, output):
        detections = output.strip().split('\n')
        self.tableWidget.setRowCount(len(detections))
        for i, line in enumerate(detections):
            parts = line.split(',')
            if len(parts) >= 2:
                self.tableWidget.setItem(i, 0, QTableWidgetItem(parts[0]))
                self.tableWidget.setItem(i, 1, QTableWidgetItem(parts[1]))
                btnDelete = QPushButton('Supprimer')
                btnDelete.clicked.connect(lambda _, row=i: self.delete_row(row))
                self.tableWidget.setCellWidget(i, 2, btnDelete)  

    def processScanResults(self, output):
        detections = output.strip().split('\n')
        self.tableWidget.setRowCount(len(detections))
        for i, line in enumerate(detections):
            parts = line.split(',')
            if len(parts) >= 2:
                self.tableWidget.setItem(i, 0, QTableWidgetItem(parts[0]))
                self.tableWidget.setItem(i, 1, QTableWidgetItem(parts[1]))
                btnDelete = QPushButton('Supprimer')
                btnDelete.clicked.connect(lambda _, row=i: self.confirm_deletion(row))
                self.tableWidget.setCellWidget(i, 2, btnDelete)

                # Bouton Supprimer pour chaque rootkit détecté
                btnDelete = QPushButton('Supprimer')
                btnDelete.clicked.connect(lambda _, row=i: self.delete_row(row))
                self.tableWidget.setCellWidget(i, 2, btnDelete)

        # Ajustement de la largeur des colonnes
        self.tableWidget.setColumnWidth(0, 200)
        self.tableWidget.setColumnWidth(1, 300)
        self.tableWidget.setColumnWidth(2, 100)

    def confirm_deletion(self, row):
        item = self.tableWidget.item(row, 1)  # Get path from the second column
        reply = QMessageBox.question(self, 'Confirmation',
                                     "Êtes-vous sûr de vouloir supprimer le rootkit situé à : {}?".format(item.text()),
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.delete_row(row, item.text())

    def delete_row(self, row, path):
        import os
        try:
            os.remove(path)  # Tries to remove the file
            print(f"Suppression réussie : {path}")
            self.tableWidget.removeRow(row)
            QMessageBox.information(self, "Suppression réussie", f"Le fichier {path} a été supprimé avec succès.")
        except Exception as e:
            QMessageBox.warning(self, "Suppression échouée", f"Impossible de supprimer le fichier {path}. Erreur: {str(e)}")
            print(f"Erreur lors de la suppression : {str(e)}")
 
    def closeEvent(self, event):
        event.ignore()
        self.hide()

class FirewallWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Manager")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("icon.png"))
        self.config_path = 'config.sys'
        self.firewall_config = {}  
        self.processes_info = self.scan_processes_firewall()
        self.load_firewall_config()  
        self.initUI()

    def load_firewall_config(self):
        """Charge la configuration du pare-feu à partir du fichier et ajuste l'UI en conséquence."""
        try:
            with open(self.config_path, 'r') as file:
                self.firewall_config = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            self.firewall_config = {}

    def initUI(self):
        mainLayout = QVBoxLayout()

        # Bouton pour ouvrir un programme à bloquer
        self.openProgramButton = QPushButton('Ouvrir programme à bloquer')
        self.openProgramButton.clicked.connect(self.openFileDialog)
        mainLayout.addWidget(self.openProgramButton)     

        self.tableWidget = QTableWidget()
        self.tableWidget.setColumnCount(5)  # PID, Name, Executable, IP/Ports, Actions
        self.tableWidget.setHorizontalHeaderLabels(['PID', 'Name', 'Executable', 'IP/Ports', 'Actions'])
        mainLayout.addWidget(self.tableWidget)

        centralWidget = QWidget()  # Créez un widget central
        centralWidget.setLayout(mainLayout)  # Appliquez le layout au widget central
        self.setCentralWidget(centralWidget)      

        self.load_data()

    def openFileDialog(self):
        options = QFileDialog.Options()
        filePath, _ = QFileDialog.getOpenFileName(self, "Sélectionner le programme à bloquer", "", "Exécutables (*.exe);;Tous les fichiers (*)", options=options)
        if filePath:
            self.addProgramToList(filePath)
            self.load_data()

    def blockProgram(self, programPath):
        # Bloque le programme en ajoutant une règle de pare-feu
        ruleName = f"Bloquer_{os.path.basename(programPath)}"
        cmd = f'netsh advfirewall firewall add rule name="{ruleName}" dir=out action=block program="{programPath}" enable=yes'
        subprocess.run(cmd, shell=True)
        QMessageBox.information(self, "Blocage effectué", f"Le programme {os.path.basename(programPath)} a été bloqué avec succès.")

    def addProgramToList(self, filePath):
        fileInfo = {
            'pid': '',
            'name': os.path.basename(filePath),
            'exe': filePath,
            'connections': 'N/A',
            'blocked': False  # Ajout d'un indicateur pour le blocage
        }
        # Insérer le programme au début de la liste pour qu'il apparaisse en haut
        self.processes_info.insert(0, fileInfo) 

    def load_data(self):
        self.tableWidget.clearContents()
        self.tableWidget.setRowCount(len(self.processes_info))
        for i, proc_info in enumerate(self.processes_info):

            self.tableWidget.setItem(i, 0, QTableWidgetItem(str(proc_info['pid'])))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(proc_info['name']))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(proc_info['exe'] or 'N/A'))
            self.tableWidget.setItem(i, 3, QTableWidgetItem(proc_info['connections'] or 'N/A'))

            self.tableWidget.setColumnWidth(0, 50)  # PID
            self.tableWidget.setColumnWidth(1, 150)  # Name
            self.tableWidget.setColumnWidth(2, 550)  # Executable
            self.tableWidget.setColumnWidth(3, 300)  # IP/Ports
            self.tableWidget.setColumnWidth(4, 200)  # Actions

            blockButton = QPushButton('Bloquer')
            unblockButton = QPushButton('Débloquer')
            blockButton.setStyleSheet("background-color: red; color: black;")
            unblockButton.setStyleSheet("background-color: green; color: black;")

            blockButton.clicked.connect(lambda _, exe=proc_info['exe'], b=blockButton, ub=unblockButton: self.block_program(exe, b, ub))
            unblockButton.clicked.connect(lambda _, exe=proc_info['exe'], ub=unblockButton, b=blockButton: self.unblock_program(exe, ub, b))
            
            # Création d'un widget pour contenir les boutons
            buttonWidget = QWidget()
            buttonLayout = QHBoxLayout()  # Corrigé ici
            buttonLayout.addWidget(blockButton)
            buttonLayout.addWidget(unblockButton)
            buttonLayout.setContentsMargins(0, 0, 0, 0)
            buttonWidget.setLayout(buttonLayout)

            self.tableWidget.setCellWidget(i, 4, buttonWidget)

            if proc_info['exe'] in self.firewall_config and self.firewall_config[proc_info['exe']]:
                self.update_button_style(blockButton, True, unblockButton)
            else:
                self.update_button_style(unblockButton, False, blockButton)

    def toggle_block_program(self, row):
        proc_info = self.processes_info[row]
        if proc_info['blocked']:
            # Logique pour débloquer
            proc_info['blocked'] = False
        else:
            # Logique pour bloquer
            proc_info['blocked'] = True
        self.load_data()

    def closeEvent(self, event):
        event.ignore()
        self.hide()

    def scan_processes_firewall(self):
        processes_info = []
        for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'connections']):
            connections = 'N/A'
            try:
                connections = ", ".join(f"{c.raddr.ip}:{c.raddr.port}" for c in proc.connections() if c.raddr)
            except psutil.AccessDenied:
                pass
            processes_info.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'exe': proc.info['exe'] or 'N/A',
                'connections': connections
            })
        return processes_info

    def save_firewall_config(self, exe, is_blocked):
        try:
            with open(self.config_path, 'r') as file:
                config = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            config = {}
        config[exe] = is_blocked
        with open(self.config_path, 'w') as file:
            json.dump(config, file)

    def load_firewall_config(self):
        try:
            with open(self.config_path, 'r') as file:
                self.firewall_config = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            self.firewall_config = {}

    def toggle_firewall_rule(self, pid, exe):
        rule_name = f"Process_{pid}"
        # Check if rule exists
        check_cmd = f"netsh advfirewall firewall show rule name={rule_name}"
        result = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
        if 'No rules match the specified criteria' in result.stdout:
            # No rule exists, block the process
            cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=out action=block program=\"{exe}\" enable=yes"
            subprocess.run(cmd, shell=True)
            print(f"Blocked {exe}")
        else:
            # Rule exists, remove it
            cmd = f"netsh advfirewall firewall delete rule name={rule_name}"
            subprocess.run(cmd, shell=True)
            print(f"Allowed {exe}")

    def block_program(self, exe, blockButton, unblockButton):
        # Logique de blocage du programme avec l'ajout de la notification
        if not exe or exe == 'N/A':
            QMessageBox.warning(self, "Erreur", "Executable non spécifié ou non accessible.")
            return
        exe_name = exe.split('\\')[-1]  # Correction de la syntaxe f-string
        rule_name = f"Block_{exe_name}"
        cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=out action=block program=\"{exe}\" enable=yes"
        subprocess.run(cmd, shell=True)
        QMessageBox.information(self, "Blocage", f"Programme bloqué : {exe}")
        self.update_button_style(blockButton, True, unblockButton)
        self.save_firewall_config(exe, True)
        
    def unblock_program(self, exe, unblockButton, blockButton):
        # Logique de déblocage du programme avec l'ajout de la notification
        if not exe or exe == 'N/A':
            QMessageBox.warning(self, "Erreur", "Executable non spécifié ou non accessible.")
            return
        exe_name = exe.split('\\')[-1]  # Correction de la syntaxe f-string
        rule_name = f"Block_{exe_name}"
        cmd = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
        subprocess.run(cmd, shell=True)
        QMessageBox.information(self, "Déblocage", f"Programme débloqué : {exe}")
        self.update_button_style(unblockButton, False, blockButton)
        self.save_firewall_config(exe, False)

    def update_button_style(self, activeButton, is_blocked, inactiveButton):
        if is_blocked:
            activeButton.setStyleSheet("background-color: red; color: white;")
            activeButton.setText("Bloqué")
        else:
            activeButton.setStyleSheet("background-color: green; color: white;")
            activeButton.setText("Débloqué")
        inactiveButton.setStyleSheet("background-color: none; color: black;")

    def block_ip(self, ip_address):
        # Exemple de commande pour ajouter une règle de blocage d'IP
        cmd = f'netsh advfirewall firewall add rule name="Block IP {ip_address}" dir=in action=block remoteip={ip_address}'
        subprocess.run(cmd, shell=True)
        # Log et/ou afficher un message utilisateur
        log_event(f"IP bloquée: {ip_address}")
        QMessageBox.information(self, "Blocage IP", f"L'adresse IP {ip_address} a été bloquée.")

    def unblock_ip(self, ip_address):
        # Exemple de commande pour supprimer la règle de blocage d'IP
        cmd = f'netsh advfirewall firewall delete rule name="Block IP {ip_address}"'
        subprocess.run(cmd, shell=True)
        # Log et/ou afficher un message utilisateur
        log_event(f"IP débloquée: {ip_address}")
        QMessageBox.information(self, "Déblocage IP", f"L'adresse IP {ip_address} a été débloquée.")

def scan_processes():
    processes_info = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'connections']):
        proc_info = {
            'PID': proc.pid,
            'Name': proc.info['name'],
            'Executable': proc.info['exe'],
            'Connections': [],
            'DLLs': []
        }
        try:
            # Pour chaque processus, tentez d'obtenir la liste des DLLs chargées
            for dll in proc.memory_maps():
                if dll.path.endswith('.dll'):
                    proc_info['DLLs'].append(dll.path)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            # Si vous ne pouvez pas accéder aux infos du processus, passez au suivant
            continue
        
        for conn in proc.info['connections']:
            if conn.status == "ESTABLISHED" and conn.raddr:
                proc_info['Connections'].append(f"{conn.raddr.ip}:{conn.raddr.port}")
        processes_info.append(proc_info)
    return processes_info

def monitor_network():
    network_activity = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == "ESTABLISHED" and conn.raddr:
            connection_info = {
                'Local Address': f"{conn.laddr.ip}:{conn.laddr.port}",
                'Remote Address': f"{conn.raddr.ip}:{conn.raddr.port}",
                'Status': conn.status
            }
            network_activity.append(connection_info)
    return network_activity

class ScanProcessWindow(QMainWindow):
    def __init__(self, firewallWindow=None):
        super().__init__()
        self.firewallWindow = firewallWindow
        self.setWindowTitle("Scan Process")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("icon.png"))
        self.tableWidget = QTableWidget()
        self.setCentralWidget(self.tableWidget)
        self.load_data()

    def load_data(self):
        processes = scan_processes()
        self.tableWidget.setColumnCount(5)  # Ajout d'une colonne pour les actions
        self.tableWidget.setHorizontalHeaderLabels(['PID', 'Name', 'Executable', 'Connections', 'Actions'])
        self.tableWidget.setRowCount(len(processes))
        for i, proc in enumerate(processes):
            self.tableWidget.setItem(i, 0, QTableWidgetItem(str(proc['PID'])))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(proc['Name']))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(proc['Executable'] or 'N/A'))
            connections = ", ".join(proc['Connections'])
            self.tableWidget.setItem(i, 3, QTableWidgetItem(connections))

            # Ajout de boutons Bloquer et Débloquer
            blockButton = QPushButton("Bloquer")
            unblockButton = QPushButton("Débloquer")
            if proc['Connections']:
                first_ip = proc['Connections'][0].split(':')[0]
                blockButton.clicked.connect(lambda _, ip=first_ip: self.block_ip(ip))
                unblockButton.clicked.connect(lambda _, ip=first_ip: self.unblock_ip(ip))
            else:
                blockButton.setDisabled(True)
                unblockButton.setDisabled(True)

            # Configuration du layout pour les boutons
            actionWidget = QWidget()
            actionLayout = QHBoxLayout()
            actionLayout.addWidget(blockButton)
            actionLayout.addWidget(unblockButton)
            actionLayout.setContentsMargins(0, 0, 0, 0)  # Supprime les marges
            actionWidget.setLayout(actionLayout)
            self.tableWidget.setCellWidget(i, 4, actionWidget)

    def block_ip(self, ip_address):
        if self.firewallWindow:
            self.firewallWindow.block_ip(ip_address)
        else:
            QMessageBox.warning(self, "Erreur", "FirewallWindow non disponible.")

    def unblock_ip(self, ip_address):
        if self.firewallWindow:
            self.firewallWindow.unblock_ip(ip_address)
        else:
            QMessageBox.warning(self, "Erreur", "FirewallWindow non disponible.")
         
    def closeEvent(self, event):
        event.ignore()
        self.hide()

class IFTOPWindow(QMainWindow):
    def __init__(self, firewallWindow=None):
        super().__init__()
        self.firewallWindow = firewallWindow
        self.setWindowTitle("IFTOP")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("icon.png"))
        self.tableWidget = QTableWidget()
        self.setCentralWidget(self.tableWidget)
        self.load_data()

    def load_data(self):
        connections = monitor_network()
        self.tableWidget.setColumnCount(4)  # Ajout d'une colonne pour les actions
        self.tableWidget.setHorizontalHeaderLabels(['Local Address', 'Remote Address', 'Status', 'Actions'])
        self.tableWidget.setRowCount(len(connections))
        for i, conn in enumerate(connections):
            self.tableWidget.setItem(i, 0, QTableWidgetItem(conn['Local Address']))
            self.tableWidget.setItem(i, 1, QTableWidgetItem(conn['Remote Address']))
            self.tableWidget.setItem(i, 2, QTableWidgetItem(conn['Status']))

            # Ajout de boutons Bloquer et Débloquer
            blockButton = QPushButton("Bloquer")
            unblockButton = QPushButton("Débloquer")
            remote_ip = conn['Remote Address'].split(':')[0]
            blockButton.clicked.connect(lambda _, ip=remote_ip: self.block_ip(ip))
            unblockButton.clicked.connect(lambda _, ip=remote_ip: self.unblock_ip(ip))

            # Configuration du layout pour les boutons
            actionWidget = QWidget()
            actionLayout = QHBoxLayout()
            actionLayout.addWidget(blockButton)
            actionLayout.addWidget(unblockButton)
            actionLayout.setContentsMargins(0, 0, 0, 0)  # Supprime les marges
            actionWidget.setLayout(actionLayout)
            self.tableWidget.setCellWidget(i, 3, actionWidget)

    def block_ip(self, ip_address):
        if self.firewallWindow:
            self.firewallWindow.block_ip(ip_address)
        else:
            QMessageBox.warning(self, "Erreur", "FirewallWindow non disponible.")

    def unblock_ip(self, ip_address):
        if self.firewallWindow:
            self.firewallWindow.unblock_ip(ip_address)
        else:
            QMessageBox.warning(self, "Erreur", "FirewallWindow non disponible.")

    def closeEvent(self, event):
        event.ignore()
        self.hide()

def create_tray_icon():
    app = QApplication(sys.argv)
    # Assurez-vous que 'icon.png' est le nom correct et que le fichier est dans le même dossier que votre script.
    # Sinon, remplacez 'icon.png' par le chemin absolu vers votre fichier d'icône.
    trayIcon = QSystemTrayIcon(QIcon("icon.png"), app)
    trayIcon.setToolTip("AVHIRAL-Guardian V2.3")

    menu = QMenu()
    logAttaquesAction = QAction("Log des Attaques")
    logAttaquesAction.triggered.connect(lambda: LogAttaquesWindow().show())
    menu.addAction(logAttaquesAction)

    # Action pour le Scan Process
    scanProcessAction = QAction("Scan Process")
    scanProcessWindow = ScanProcessWindow()  # Créez une instance de votre fenêtre ici pour éviter de la recréer à chaque fois
    scanProcessAction.triggered.connect(scanProcessWindow.show)
    menu.addAction(scanProcessAction)

    # Action pour Firewall
    menu = QMenu()
    openAction = QAction("Open Firewall Manager", self)
    openAction.triggered.connect(self.showFirewallWindow)
    menu.addAction(openAction)

    # Action pour IFTOP
    iftopAction = QAction("IFTOP")
    iftopWindow = IFTOPWindow()  # Créez une instance de votre fenêtre ici pour éviter de la recréer à chaque fois
    iftopAction.triggered.connect(iftopWindow.show)
    menu.addAction(iftopAction)

    # Menu for the tray icon
    menu = QMenu()
    open_keyboard = QAction("Open AntiKeylogger Keyboard", app)
    open_keyboard.triggered.connect(open_keyboard_window)
    menu.addAction(open_keyboard)

    infosGuardianAction = QAction("Infos Guardian")
    infosGuardianAction.triggered.connect(lambda: InfosGuardianWindow().show())
    menu.addAction(infosGuardianAction)

    startupOptionAction = QAction("Option Démarrage", self)
    startupOptionAction.triggered.connect(self.showStartupOptionWindow)
    menu.addAction(startupOptionAction)

    quitAction = QAction("Quitter Guardian")
    quitAction.triggered.connect(QCoreApplication.instance().quit)
    menu.addAction(quitAction)

    trayIcon.setContextMenu(menu)
    trayIcon.show()
    sys.exit(app.exec_())

class LogAttaquesWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Logs des Attaques")
        self.setGeometry(100, 100, 600, 400)
        self.setWindowIcon(QIcon("icon.png"))
        self.textEdit = QTextEdit()
        self.textEdit.setReadOnly(True)
        self.setCentralWidget(self.textEdit)

    def showEvent(self, event):
        # Crée le fichier de log juste avant d'ouvrir la fenêtre
        log_event("Ouverture du journal des attaques.")
        self.updateLogs()

    def closeEvent(self, event):
        # Efface le fichier de log à la fermeture de la fenêtre
        if os.path.exists("log.log"):
            os.remove("log.log")
        event.ignore()
        self.hide()

    def updateLogs(self):
        if os.path.exists("log.log"):
            with open("log.log", "r") as log_file:
                self.textEdit.setText(log_file.read())
        else:
            self.textEdit.setText("Fichier de log introuvable.")

class ClickableLabel(QLabel):
    clicked = pyqtSignal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setCursor(Qt.PointingHandCursor) 
        self.setTextFormat(Qt.RichText)
        self.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.setOpenExternalLinks(False) 
        self.setStyleSheet("QLabel { color: blue; text-decoration: underline; }")  

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.clicked.emit() 

class InfosGuardianWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Informations sur AVHIRAL-Guardian V2.3")
        self.setGeometry(100, 100, 500, 800)
        self.setWindowIcon(QIcon("icon.png"))

        layout = QVBoxLayout()

        # Centrer l'image du logo
        logoLabel = QLabel()
        logoLabel.setAlignment(Qt.AlignCenter)
        logoLabel.setPixmap(QPixmap("logo.png"))
        layout.addWidget(logoLabel)

        # Texte d'information et e-mail en tant que ClickableLabel
        infoText = """<center><b>AVHIRAL-Guardian V2.3 (version finale)</b> - <strong>Freeware</strong><br>
<u><strong>Code :</strong></u> <strong>David PILATO</strong><br>
<a href="https://www.avhiral.com">www.avhiral.com</a></center>"""
        infoLabel = QLabel(infoText)
        infoLabel.setOpenExternalLinks(True)
        layout.addWidget(infoLabel)

        emailLabel = ClickableLabel("<a href='mailto:contact@avhiral.com'>contact@avhiral.com</a>")
        emailLabel.clicked.connect(lambda: webbrowser.open("mailto:contact@avhiral.com"))
        emailLabel.setAlignment(Qt.AlignCenter)
        layout.addWidget(emailLabel)

        donateButton = QPushButton("Faire un don")
        donateButton.clicked.connect(lambda: webbrowser.open("https://www.paypal.com/donate/?hosted_button_id=FSX7RHUT4BDRY"))
        layout.addWidget(donateButton)

        donateLabel = QLabel()
        donateLabel.setAlignment(Qt.AlignCenter)
        donateLabel.setPixmap(QPixmap("don.png"))
        layout.addWidget(donateLabel)

        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)

        # Section des mesures de protection
        protectionsLabel = QLabel("<b>Mesures de protection intégrées:</b>")
        layout.addWidget(protectionsLabel)

        # Liste des mesures de protection
        protections = [
            ("Anti-Ransomware", "Surveillance active des modifications de fichiers suspects pour prévenir les attaques de ransomware."),
            ("Anti-Trojan", "Analyse périodique des fichiers exécutables pour détecter les signatures de trojans."),
            ("Surveillance réseau", "Contrôle des connexions réseau pour identifier les activités suspectes."),
            ("Protection Thunderbird", "Vérification de l'intégrité des installations de Thunderbird pour éviter les altérations."),
            ("Chiffrement de mot de passe", "Chiffrement sécurisé des mots de passe stockés sur le système."),
            ("Anti-Keylogger", "Protection contre les logiciels de capture de frappes pour sécuriser vos saisies."),
            ("Blocage IP", "Blocage des adresses IP suspectes pour prévenir les intrusions."),
            ("Surveillance des processus", "Analyse en temps réel des processus en cours pour détecter les comportements malveillants."),
            ("Gestion du pare-feu", "Contrôle avancé des règles de pare-feu pour une meilleure défense réseau."),
            ("Anti-Rootkit", "Détection et suppression des rootkits pour protéger le système d'exploitations cachées.")
        ]

        for title, desc in protections:
            protectionTitle = QLabel(f"<b>{title}:</b>")
            protectionDesc = QLabel(desc)
            protectionDesc.setWordWrap(True)
            layout.addWidget(protectionTitle)
            layout.addWidget(protectionDesc)

        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)
        self.setFixedSize(self.size())

    def closeEvent(self, event):
        event.ignore()
        self.hide()

class FileMonitoringThread(QThread):
    def __init__(self, guardian):
        QThread.__init__(self)
        self.guardian = guardian

    def run(self):
        self.guardian.block_ddos_attacks()
        self.guardian.block_malicious_robots()
        self.guardian.detect_trojans()

class FileMonitoringThread(QThread):
    def __init__(self, file_path, interval=5):
        super().__init__()
        self.file_path = file_path
        self.interval = interval
        self.last_hash = None

    def run(self):
        while True:
            self.check_file_modification()
            QThread.sleep(self.interval)

    def check_file_modification(self):
        try:
            with open(self.file_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
                if self.last_hash is not None and self.last_hash != current_hash:
                    print(f"Modification détectée dans le fichier : {self.file_path}")
                self.last_hash = current_hash
        except FileNotFoundError:
            print(f"Le fichier {self.file_path} n'a pas été trouvé.")

class GuardianProtection:
    def __init__(self):
        # Initialisation de variables pour suivre les connexions
        self.connections_count = {}
        self.block_threshold = 100
        self.blocked_ips = {} 
        self.block_duration = 300  
        self.connections_count = {}

    def start_protection(self):
        # Démarre la surveillance en background
        QTimer.singleShot(0, self.protection_loop)
        """Démarre la surveillance du réseau pour la détection d'attaques DDOS."""
        self.block_ddos_attacks()
        self.block_malicious_robots()
        self.detect_trojans()

    def protection_loop(self):
        # Boucle de protection effectuant les vérifications
        detect_suspicious_processes()
        monitor_network_activity(self.block_threshold)
        QTimer.singleShot(10000, self.protection_loop)

    def block_ddos_attacks(self):
        """Vérifie les connexions réseau pour détecter une activité suspecte."""
        while True:
            current_connections = psutil.net_connections(kind='inet')
            for conn in current_connections:
                # Filtrer par connexions établies et ignorer les adresses locales
                if conn.status == "ESTABLISHED" and conn.raddr:
                    ip_address = conn.raddr.ip
                    self.connections_count[ip_address] = self.connections_count.get(ip_address, 0) + 1

                    # Vérifier si le nombre de connexions dépasse le seuil
                    if self.connections_count[ip_address] > self.block_threshold:
                        log_event(f"Activité suspecte détectée: {ip_address} a dépassé le seuil de connexions")
                        # Ici, vous pouvez ajouter des mesures pour bloquer l'adresse IP ou alerter l'administrateur

            # Réinitialiser le comptage périodiquement pour éviter les faux positifs
            self.connections_count.clear()
            time.sleep(10)

    def block_malicious_robots(self):
        allowed_user_agents = ['Googlebot', 'Bingbot', 'Amazonbot', 'Yandexbot', 'SemrushBot', 'AhrefsBot']
        for process in psutil.process_iter(['pid', 'name']):
            if 'httpd' in process.info['name']:
                headers = process.get_http_headers()
                if 'user-agent' in headers:
                    user_agent = headers['user-agent']
                    if user_agent not in allowed_user_agents:
                        # Stratégie de blocage adaptative - temporairement bloquer l'adresse IP
                        ip_address = process.get_remote_address()
                        self.block_ip_address(ip_address)

    def block_ip_address(self, ip_address):
        # Vérifie si l'adresse IP est déjà bloquée
        if ip_address not in self.blocked_ips:
            # Ajoute l'adresse IP au dictionnaire avec le temps de blocage actuel
            self.blocked_ips[ip_address] = time.time()
            # Planifie une tâche pour débloquer l'adresse IP après la durée spécifiée
            threading.Timer(self.block_duration, self.unblock_ip_address, args=[ip_address]).start()

    def unblock_ip_address(self, ip_address):
        # Vérifie si l'adresse IP est dans le dictionnaire
        if ip_address in self.blocked_ips:
            # Supprime l'entrée de l'adresse IP dans le dictionnaire
            del self.blocked_ips[ip_address]

    def detect_trojans(self):
        # Liste des répertoires où rechercher les fichiers exécutables suspects
        suspicious_dirs = ['/usr/bin', '/bin', '/sbin', '/usr/sbin', '/usr/local/bin']
        for s_dir in suspicious_dirs:
            for file_name in os.listdir(s_dir):
                if file_name.endswith('.exe') or file_name.endswith('.dll'):
                    file_path = os.path.join(s_dir, file_name)
                    if self.is_known_trojan(file_path):
                        try:
                            os.remove(file_path)
                            log_event(f"Trojan détecté et supprimé: {file_name} [{file_path}]")
                        except Exception as e:
                            log_event(f"Erreur lors de la suppression du fichier: {file_name} [{file_path}]. {str(e)}")

    def is_known_trojan(self, file_path):
        # Vérifie si le hachage du fichier est connu comme étant associé à un trojan
        known_hashes = {
            'remote_desktop.exe': 'hash_value_1',
            'keylogger.exe': 'hash_value_2',
            'backdoor.exe': 'hash_value_3'
        }
        if os.path.exists(file_path):
            file_hash = self.get_file_hash(file_path)
            file_name = os.path.basename(file_path)
            return file_name in known_hashes and known_hashes[file_name] == file_hash
        return False

    def get_file_hash(self, file_path):
        # Calcule le hachage du fichier
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
        except Exception as e:
            log_event(f"Erreur lors du calcul du hachage pour le fichier: {file_path}. {str(e)}")
            return None
        return hasher.hexdigest()

    def get_known_hash(self, file_path):
        # Fonction pour obtenir un hachage connu pour un fichier donné
        # Cette fonction récupère la clé de registre pour le hachage connu
        # dans l'entrée associée au fichier spécifié.
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Guardian", 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, file_path)
                return value
        except FileNotFoundError:
            return None
        except Exception as e:
            log_event(f"Erreur lors de la récupération du hachage connu pour le fichier: {file_path}. {str(e)}")
            return None

def create_tray_icon():
    # Assurez-vous que 'icon.png' est le nom correct et que le fichier est dans le même dossier que votre script.
    trayIcon = QSystemTrayIcon(QIcon("icon.png"), app)
    trayIcon.setToolTip("AVHIRAL-Guardian V2.3")

    # Création du menu contextuel pour l'icône de la barre des tâches
    menu = QMenu()
    logAttaquesAction = QAction("Log des Attaques")
    logAttaquesAction.triggered.connect(lambda: LogAttaquesWindow().show())
    menu.addAction(logAttaquesAction)

    # Action pour le Scan Process
    scanProcessAction = QAction("Scan Process")
    scanProcessWindow = ScanProcessWindow()  # Créez une instance de votre fenêtre ici pour éviter de la recréer à chaque fois
    scanProcessAction.triggered.connect(scanProcessWindow.show)
    menu.addAction(scanProcessAction)

    # Action pour IFTOP
    iftopAction = QAction("IFTOP")
    iftopWindow = IFTOPWindow()  # Créez une instance de votre fenêtre ici pour éviter de la recréer à chaque fois
    iftopAction.triggered.connect(iftopWindow.show)
    menu.addAction(iftopAction)

    infosGuardianAction = QAction("Infos Guardian")
    infosGuardianAction.triggered.connect(lambda: InfosGuardianWindow().show())
    menu.addAction(infosGuardianAction)

    startupOptionAction = QAction("Option Démarrage", self)
    startupOptionAction.triggered.connect(self.showStartupOptionWindow)
    menu.addAction(startupOptionAction)

    quitAction = QAction("Quitter Guardian")
    quitAction.triggered.connect(QCoreApplication.instance().quit)
    menu.addAction(quitAction)

    trayIcon.setContextMenu(menu)
    trayIcon.show()

class FileMonitoringThread(QThread):
    def __init__(self, guardian):
        super().__init__()
        self.guardian = guardian

    def run(self):
        # Ici, lancez toutes vos vérifications de sécurité
        self.guardian.block_ddos_attacks()
        self.guardian.block_malicious_robots()
        self.guardian.detect_trojans()

if __name__ == "__main__":
    afficher_image()
    import sys
    app = App(sys.argv)
    guardian_protection = GuardianProtection()
    file_monitoring_thread = FileMonitoringThread(guardian_protection)
    file_monitoring_thread.start()
    sys.exit(app.exec_())
    