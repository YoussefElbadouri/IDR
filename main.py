#search the comments and do what they say :)

from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QTextEdit, QComboBox, QStackedWidget, QFileDialog, QSpacerItem, QSizePolicy
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QPalette, QBrush, QPixmap, QColor
import psutil
import socket
from scapy.all import rdpcap, sniff, IP, TCP, UDP, ICMP
import re
from collections import defaultdict
import matplotlib.pyplot as plt
from fpdf import FPDF
import os
import json
import pandas as pd
import seaborn as sns
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Custom QPushButton class that changes color when hovered or clicked
class HoverButton(QPushButton):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_color = self.palette().color(QPalette.Button)
        self.hover_color = QColor(173, 216, 230, 178)  # Light blue with 0.7 opacity
        self.clicked_color = QColor(144, 238, 144, 178)  # Light green with 0.7 opacity
        self.setMouseTracking(True)
        self.installEventFilter(self)

    def enterEvent(self, event):
        self.setStyleSheet(
            f"background-color: rgba({self.hover_color.red()}, {self.hover_color.green()}, {self.hover_color.blue()}, {self.hover_color.alpha() / 255});")
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setStyleSheet(f"background-color: {self.default_color.name()};")
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        self.setStyleSheet(
            f"background-color: rgba({self.clicked_color.red()}, {self.clicked_color.green()}, {self.clicked_color.blue()}, {self.clicked_color.alpha() / 255});")
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.setStyleSheet(
            f"background-color: rgba({self.hover_color.red()}, {self.hover_color.green()}, {self.hover_color.blue()}, {self.hover_color.alpha() / 255});")
        super().mouseReleaseEvent(event)


# QThread subclass for sniffing network packets
class PacketSnifferThread(QThread):
    packet_received = pyqtSignal(str, str)

    def __init__(self, interface, selected_filter):
        super().__init__()
        self.interface = interface
        self.selected_filter = selected_filter
        self.running = True

    def run(self):
        sniff(iface=self.interface, prn=self.process_packet, store=0, stop_filter=self.should_stop)

    def process_packet(self, packet):
        if self.selected_filter in ["TCP", "IP", "UDP", "ICMP"]:
            if self.selected_filter == "TCP" and packet.haslayer(TCP):
                self.emit_packet(packet, "TCP")
            elif self.selected_filter == "IP" and packet.haslayer(IP):
                self.emit_packet(packet, "IP")
            elif self.selected_filter == "UDP" and packet.haslayer(UDP):
                self.emit_packet(packet, "UDP")
            elif self.selected_filter == "ICMP" and packet.haslayer(ICMP):
                self.emit_packet(packet, "ICMP")
        else:
            # If "All Protocols" is selected, process all relevant packets
            if packet.haslayer(IP):
                if packet.haslayer(TCP):
                    self.emit_packet(packet, "TCP")
                elif packet.haslayer(UDP):
                    self.emit_packet(packet, "UDP")
                elif packet.haslayer(ICMP):
                    self.emit_packet(packet, "ICMP")

    def emit_packet(self, packet, protocol):
        for rule in parsed_rules:
            if rule_matches_packet(rule, packet):
                alert_msg = f"Alert: {rule['options']['msg']} - {packet[IP].src} -> {packet[IP].dst} ({protocol})"
                severity = rule['options'].get('severity', 'Unknown')
                self.packet_received.emit(alert_msg, severity)

    def should_stop(self, packet):
        return not self.running

    def stop(self):
        self.running = False


# Main window class for the application
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("IDR Application")
        self.setGeometry(100, 100, 800, 600)

        # Set background image
        self.set_background_image('background_idr.png')

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        self.init_ui()
        self.sniffer_thread = None
        self.alerts = defaultdict(lambda: {'count': 0, 'severity': 'Unknown'})  # To store and count alerts

        # Load methodologies
        self.load_methodologies()

    def set_background_image(self, image_path):
        oImage = QPixmap(image_path)
        sImage = oImage.scaled(self.size())
        palette = QPalette()
        palette.setBrush(QPalette.Window, QBrush(sImage))
        self.setPalette(palette)

    def resizeEvent(self, event):
        self.set_background_image('background_idr.png')
        super(MainWindow, self).resizeEvent(event)

    def init_ui(self):
        # Home page
        self.home_page = QWidget()
        home_layout = QVBoxLayout()

        scan_live_button = HoverButton("Scan Live")
        scan_live_button.setFixedSize(700, 40)  # Set button size
        scan_live_button.clicked.connect(self.show_scan_live_page)

        analyze_pcap_button = HoverButton("Analyser un Fichier Pcap")
        analyze_pcap_button.setFixedSize(700, 40)  # Set button size
        analyze_pcap_button.clicked.connect(self.show_analyze_pcap_page)

        # Create a horizontal layout to center buttons
        button_layout = QHBoxLayout()
        button_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        button_layout.addWidget(scan_live_button)
        button_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        home_layout.addLayout(button_layout)

        button_layout = QHBoxLayout()
        button_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        button_layout.addWidget(analyze_pcap_button)
        button_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        home_layout.addLayout(button_layout)

        self.home_page.setLayout(home_layout)

        # Scan live page
        self.scan_live_page = QWidget()
        scan_live_layout = QVBoxLayout()

        self.interface_label = QLabel("Sélectionner une interface :")
        self.interface_label.setStyleSheet("color: white;")
        scan_live_layout.addWidget(self.interface_label)

        self.interface_combo = QComboBox()
        self.interface_combo.setFixedSize(700, 40)  # Set combo box size
        self.interface_combo.addItems(get_active_network_interfaces())
        scan_live_layout.addWidget(self.interface_combo)

        self.filter_label = QLabel("Sélectionner un filtre :")
        self.filter_label.setStyleSheet("color: white;")
        scan_live_layout.addWidget(self.filter_label)

        self.filter_combo = QComboBox()
        self.filter_combo.setFixedSize(700, 40)  # Set combo box size
        self.filter_combo.addItems(["Tous les protocols", "TCP", "IP", "UDP", "ICMP"])
        scan_live_layout.addWidget(self.filter_combo)

        self.realtime_button = HoverButton("Démarrer l'Analyse en Temps Réel")
        self.realtime_button.setFixedSize(700, 40)  # Set button size
        self.realtime_button.clicked.connect(self.start_realtime_analysis)
        scan_live_layout.addWidget(self.realtime_button)

        self.stop_button = HoverButton("Arrêter l'Analyse en Temps Réel")
        self.stop_button.setFixedSize(700, 40)  # Set button size
        self.stop_button.clicked.connect(self.stop_realtime_analysis)
        scan_live_layout.addWidget(self.stop_button)

        self.alert_label = QLabel("Résultat du scan")
        self.alert_label.setStyleSheet("color: white;")
        scan_live_layout.addWidget(self.alert_label)

        self.alerts_display = QTextEdit()
        self.alerts_display.setReadOnly(True)
        scan_live_layout.addWidget(self.alerts_display)

        self.report_button = HoverButton("Voir le Rapport")
        self.report_button.setFixedSize(700, 40)  # Set button size
        self.report_button.clicked.connect(self.show_report_page)
        self.report_button.setVisible(False)  # Hide the button initially
        scan_live_layout.addWidget(self.report_button)

        self.heatmap_button = HoverButton("Afficher le Heatmap")
        self.heatmap_button.setFixedSize(700, 40)  # Set button size
        self.heatmap_button.clicked.connect(self.show_heatmap)
        self.heatmap_button.setVisible(False)  # Hide the button initially
        scan_live_layout.addWidget(self.heatmap_button)

        # Create a horizontal layout to center the elements
        h_layout = QHBoxLayout()
        h_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        h_layout.addLayout(scan_live_layout)
        h_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.scan_live_page.setLayout(h_layout)

        # Analyze pcap file page
        self.analyze_pcap_page = QWidget()
        analyze_pcap_layout = QVBoxLayout()

        self.file_label = QLabel("Sélectionner un fichier Pcap :")
        analyze_pcap_layout.addWidget(self.file_label)

        self.file_button = HoverButton("Choisir Fichier")
        self.file_button.setFixedSize(700, 40)  # Set button size
        self.file_button.clicked.connect(self.open_file_dialog)
        analyze_pcap_layout.addWidget(self.file_button)

        self.pcap_alert_label = QLabel("Résultat du scan")
        self.pcap_alert_label.setStyleSheet("color: white;")
        analyze_pcap_layout.addWidget(self.pcap_alert_label)

        self.pcap_alerts_display = QTextEdit()
        self.pcap_alerts_display.setReadOnly(True)
        analyze_pcap_layout.addWidget(self.pcap_alerts_display)

        self.pcap_report_button = HoverButton("Voir le Rapport")
        self.pcap_report_button.setFixedSize(700, 40)  # Set button size
        self.pcap_report_button.clicked.connect(self.show_report_page)
        self.pcap_report_button.setVisible(False)  # Hide the button initially
        analyze_pcap_layout.addWidget(self.pcap_report_button)

        self.pcap_heatmap_button = HoverButton("Afficher le Heatmap")
        self.pcap_heatmap_button.setFixedSize(700, 40)  # Set button size
        self.pcap_heatmap_button.clicked.connect(self.show_heatmap)
        self.pcap_heatmap_button.setVisible(False)  # Hide the button initially
        analyze_pcap_layout.addWidget(self.pcap_heatmap_button)

        # Create a horizontal layout to center the elements
        h_pcap_layout = QHBoxLayout()
        h_pcap_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        h_pcap_layout.addLayout(analyze_pcap_layout)
        h_pcap_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.analyze_pcap_page.setLayout(h_pcap_layout)

        # Report page
        self.report_page = QWidget()
        report_layout = QVBoxLayout()
        self.report_label = QLabel("Rapport d'analyse")
        self.report_label.setStyleSheet("color: white;")
        report_layout.addWidget(self.report_label)

        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        report_layout.addWidget(self.report_text)

        self.save_button = HoverButton("Sauvegarder le Rapport")
        self.save_button.setFixedSize(700, 40)  # Set button size
        self.save_button.clicked.connect(self.save_report)
        report_layout.addWidget(self.save_button)

        self.methodology_button = HoverButton("Voir la Méthodologie")
        self.methodology_button.setFixedSize(700, 40)  # Set button size
        self.methodology_button.clicked.connect(self.show_methodology_page)
        report_layout.addWidget(self.methodology_button)

        self.report_page.setLayout(report_layout)

        # Methodology page
        self.methodology_page = QWidget()
        methodology_layout = QVBoxLayout()
        self.methodology_label = QLabel("Méthodologie de Réponse aux Incidents")
        self.methodology_label.setStyleSheet("color: white;")
        methodology_layout.addWidget(self.methodology_label)

        self.methodology_text = QTextEdit()
        self.methodology_text.setReadOnly(True)
        methodology_layout.addWidget(self.methodology_text)

        self.methodology_page.setLayout(methodology_layout)

        # Add pages to QStackedWidget
        self.stacked_widget.addWidget(self.home_page)
        self.stacked_widget.addWidget(self.scan_live_page)
        self.stacked_widget.addWidget(self.analyze_pcap_page)
        self.stacked_widget.addWidget(self.report_page)
        self.stacked_widget.addWidget(self.methodology_page)

        # Show home page
        self.stacked_widget.setCurrentWidget(self.home_page)

    def show_scan_live_page(self):
        self.stacked_widget.setCurrentWidget(self.scan_live_page)

    def show_analyze_pcap_page(self):
        self.stacked_widget.setCurrentWidget(self.analyze_pcap_page)

    def show_report_page(self):
        self.stacked_widget.setCurrentWidget(self.report_page)
        self.generate_report()

    def show_methodology_page(self):
        self.stacked_widget.setCurrentWidget(self.methodology_page)
        self.generate_methodology()

    def open_file_dialog(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier Pcap", "",
                                                   "Fichiers Pcap (*.pcap);;Tous les fichiers (*)", options=options)
        if file_name:
            self.analyze_pcap_file(file_name)

    def analyze_pcap_file(self, file_name):
        self.alerts.clear()  # Clear previous alerts
        packets = rdpcap(file_name)
        self.pcap_alerts_display.append(f"Analyse du fichier : {file_name}")
        for packet in packets:
            if packet.haslayer(IP):
                self.process_packet(packet)
        self.display_pcap_alerts()
        self.pcap_report_button.setVisible(True)  # Show the report button
        self.pcap_heatmap_button.setVisible(True)  # Show the heatmap button

    def process_packet(self, packet):
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "IP"

        for rule in parsed_rules:
            if rule_matches_packet(rule, packet):
                alert_msg = f"Alert: {rule['options']['msg']} - {packet[IP].src} -> {packet[IP].dst} ({protocol})"
                severity = rule['options'].get('severity', 'Unknown')
                self.handle_alert(alert_msg, severity)

    def start_realtime_analysis(self):
        selected_interface = self.interface_combo.currentText()
        selected_filter = self.filter_combo.currentText()
        self.alerts.clear()  # Clear previous alerts
        self.alerts_display.clear()  # Clear the display area
        self.alerts_display.setTextColor(QColor(0, 0, 0))  # Set text color to black
        self.alerts_display.append(
            f"Analyse en temps réel démarrée sur l'interface {selected_interface} avec le filtre {selected_filter}...")
        self.sniffer_thread = PacketSnifferThread(selected_interface, selected_filter)
        self.sniffer_thread.packet_received.connect(self.handle_alert)
        self.sniffer_thread.start()

    def stop_realtime_analysis(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.sniffer_thread = None
        self.display_alerts()
        self.report_button.setVisible(True)  # Show the report button
        self.heatmap_button.setVisible(True)  # Show the heatmap button
        self.send_alert_email_with_ip_list("Analysis stopped. Please review the alerts detected during the analysis.")

    def handle_alert(self, message, severity):
        self.alerts[message] = {'count': self.alerts[message]['count'] + 1, 'severity': severity}
        self.display_alert(message)
        if severity in ["high", "medium"]:
            self.send_alert_email_with_ip_list(message)

    def display_alert(self, message):
        self.alerts_display.append(message)

    def display_alerts(self):
        self.alerts_display.clear()
        if self.alerts:
            for alert, details in self.alerts.items():
                self.alerts_display.append(f"{alert} - Detected {details['count']} times")
        else:
            self.alerts_display.append("Aucune alerte détectée.")

    def display_pcap_alerts(self):
        self.pcap_alerts_display.clear()
        self.pcap_alerts_display.setTextColor(QColor(0, 0, 0))  # Set text color to black
        if self.alerts:
            for alert, details in self.alerts.items():
                self.pcap_alerts_display.append(f"{alert} - Detected {details['count']} times")
        else:
            self.pcap_alerts_display.append("Aucune alerte détectée.")

    def generate_report(self):
        report_text = "Rapport d'analyse :\n\n"
        for alert, details in self.alerts.items():
            report_text += f"{alert} - Detected {details['count']} times\n"

        # Example of adding a chart to the report
        fig, ax = plt.subplots()
        alerts = list(self.alerts.keys())
        counts = [details['count'] for details in self.alerts.values()]
        labels = [alert.split("->")[1].strip() for alert in alerts]  # Use IPs for labels
        ax.barh(labels, counts, color='blue')
        ax.set_xlabel('Nombre de détections')
        ax.set_title('Graphique des alertes détectées')

        plt.tight_layout()
        plt.savefig('report_chart.png')

        report_text += "\n\nGraphique des alertes détectées :\n"
        report_text += '<img src="report_chart.png">\n'

        self.report_text.setHtml(report_text)

    def save_report(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Sauvegarder le rapport", "", "PDF Files (*.pdf);;All Files (*)")
        if file_path:
            self.create_pdf_report(file_path)

    def create_pdf_report(self, file_path):
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", size=12)
        for alert, details in self.alerts.items():
            pdf.cell(200, 10, txt=f"{alert} - Detected {details['count']} times", ln=True, align='L')

        pdf.image('report_chart.png', x=10, y=None, w=190)

        pdf.output(file_path)
        os.remove('report_chart.png')  # Remove the image file after saving the PDF

    def load_methodologies(self):
        # Load methodologies from a JSON file
        with open('methodologies.json', 'r') as file:
            self.methodologies = json.load(file)

    def generate_methodology(self):
        methodology_text = "Méthodologie de Réponse aux Incidents :\n\n"
        for step in self.methodologies['steps']:
            methodology_text += f"Étape : {step['name']}\n"
            methodology_text += f"Description : {step['description']}\n"
            methodology_text += "Actions :\n"
            for action in step['actions']:
                methodology_text += f" - {action}\n"
            methodology_text += "\n"
        self.methodology_text.setText(methodology_text)

    def show_heatmap(self):
        ip_counts = defaultdict(lambda: {'count': 0, 'severity': 'Unknown'})
        for alert, details in self.alerts.items():
            ip = alert.split("->")[1].strip()
            ip_counts[ip]['count'] += details['count']
            ip_counts[ip]['severity'] = details['severity']

        ip_list = list(ip_counts.keys())
        count_list = [details['count'] for details in ip_counts.values()]
        severity_list = [details['severity'] for details in ip_counts.values()]

        df = pd.DataFrame({
            "IP": ip_list,
            "Count": count_list,
            "Severity": severity_list
        })

        plt.figure(figsize=(10, 8))
        heatmap_data = df.pivot_table(index='IP', values='Count', aggfunc='sum')
        sns.heatmap(heatmap_data, annot=True, fmt='d', cmap='YlGnBu')
        plt.title('Heatmap des Alertes')
        plt.show()

    def send_alert_email_with_ip_list(self, alert_msg):
        to_email = "ysfelb77@gmail.com" #put the email of the administrator
        subject = "Medium or High Severity Alert Detected"
        body = f"A medium or high severity alert was detected:\n\n{alert_msg}\n\n"

        ip_list = [alert.split("->")[1].strip() for alert, details in self.alerts.items() if details['severity'] in ["high", "medium"]]
        if ip_list:
            body += "Please review the following IP addresses for potential issues:\n" + "\n".join(ip_list)
        else:
            body += "No IP addresses found for medium or high severity alerts."

        server = 'smtp.gmail.com'
        port = 587
        from_email = "insay.py@gmail.com"
        password = "hlmc rgyz mvnd hlvk"

        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg['From'] = from_email
        msg['To'] = to_email

        part1 = MIMEText(body, "plain")
        msg.attach(part1)

        try:
            with smtplib.SMTP(server, port) as server:
                server.starttls()
                server.login(from_email, password)
                server.send_message(msg)
            print('Alert email sent successfully.')
        except Exception as e:
            print(f'Failed to send alert email: {e}')


# Get active network interfaces
def get_active_network_interfaces():
    interfaces = psutil.net_if_addrs()
    active_interfaces = []
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                active_interfaces.append(interface)
                break
    return active_interfaces


# Parse a Snort rule
def parse_snort_rule(rule):
    regex = r'(\w+)\s+(\w+)\s+(\$?\w+)\s+(\d+|\w+)\s+->\s+(\$?\w+)\s+(\d+|\w+)\s+\((.+)\)'
    match = re.match(regex, rule)
    if match:
        action, proto, src_ip, src_port, dst_ip, dst_port, options = match.groups()
        options_dict = {}
        options_list = options.split(';')
        for option in options_list:
            if ':' in option:
                key, value = option.split(':', 1)
                options_dict[key.strip()] = value.strip()
        return {
            "action": action,
            "proto": proto,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "options": options_dict
        }
    return None


# Check if a rule matches a packet
def rule_matches_packet(rule, packet):
    if rule['proto'].lower() != 'tcp':
        return False
    if rule['src_ip'] != '$HOME_NET' and rule['src_ip'] != packet[IP].src:
        return False
    if rule['dst_ip'] != '$EXTERNAL_NET' and rule['dst_ip'] != packet[IP].dst:
        return False
    if rule['src_port'] != 'any' and rule['src_port'] != str(packet[TCP].sport):
        return False
    if rule['dst_port'] != 'any' and rule['dst_port'] != str(packet[TCP].dport):
        return False
    return True


# Load and parse Snort rules
rules_file_path = '/Users/youssefelbadouri/Desktop/snort3-community-rules/snort3-community.rules' #put the path of your snort file
with open(rules_file_path, 'r') as file:
    snort_rules = file.readlines()

parsed_rules = [parse_snort_rule(rule) for rule in snort_rules]
parsed_rules = [rule for rule in parsed_rules if rule is not None]

if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())
