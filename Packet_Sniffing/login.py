import scapy.all as scapy
from scapy.layers import http


def sniffing(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    print(packet.show())  # Shows full packet details for analysis

    if packet.haslayer(http.HTTPRequest):  # Check if the packet contains an HTTP request
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"📡 HTTP Request to: {url}")

        if packet.haslayer(scapy.Raw):  # Check if raw data (form data) is present
            raw_data = packet[scapy.Raw].load.decode(errors="ignore")  # Decode safely
            print("📥 Possible Form Data Detected:")
            print(raw_data)

            # Look for login-related keywords in the captured data
            keywords = ["username", "user", "login", "email", "password", "pass", "pwd"]
            found_keywords = [keyword for keyword in keywords if keyword in raw_data.lower()]

            if found_keywords:
                print("\n⚠️ WARNING: Suspicious credential capture detected!")
                print(f"🔍 Extracted Fields: {', '.join(found_keywords)}")
                print("🛑 If this is a malicious script, REMOVE these lines immediately!\n")

                # Show the exact lines that need to be removed
                suspicious_lines = [
                    "if packet.haslayer(scapy.Raw):",
                    "raw_data = packet[scapy.Raw].load.decode(errors=\"ignore\")",
                    "print(raw_data)",
                    "if keyword in raw_data.lower()",
                    "print(f\"⚠️ WARNING: This script is attempting to capture {keyword}!\")"
                ]
                print("🚨 Remove or modify the following lines in any untrusted script:")
                for line in suspicious_lines:
                    print(f"❌ {line}")


sniffing("Wi-Fi")  # Replace with your correct network interface
