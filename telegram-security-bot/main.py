from dotenv import load_dotenv
import os
import random
import logging
import validators
import tldextract
import requests
import idna
from telegram.update import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, Dispatcher, CallbackContext
from flask import Flask
from threading import Thread


load_dotenv()  # Load environment variables from .env file
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_API_KEY")

#set up logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Load environment variables from .env into os.environ---
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise RuntimeError(
        "❌ BOT_TOKEN not found. Please set it in your .env file")


# --- Command Handlers ---
def start(update, context: CallbackContext) -> None:
    update.message.reply_text(
        "👋 Hello! I’m SecGuard, your digital security buddy.\n\n"
        "Type /tip to get cybersecurity tips.\n"
        "Type /checklink <URL> to check if a link is safe.")


tips_pool = [
    "🔑 Use strong passwords with at least 12 characters.",
    "📱 Don’t share your OTP or verification codes with anyone.",
    "🌐 Always check website addresses to ensure it's secured before entering credentials.",
    "💻 Update your software regularly to patch vulnerabilities.",
    "🚫 Avoid clicking suspicious links in emails or messages.",
    "🛡️ Enable two-factor authentication (2FA) on all important accounts.",
    "🔒 Lock your phone and computer when not in use.",
    "☁️ Don’t store sensitive info in plain text on cloud drives.",
    "📧 Beware of emails that create urgency — they may be phishing.",
    "📵 Avoid using public Wi-Fi for banking or shopping.",
    "🕵️ Check app permissions before installing on your phone.",
    "🧹 Clear your browser cache and cookies regularly.",
    "🔔 Monitor your bank statements for unknown charges.",
    "🔄 Back up important files regularly to an external drive or in the cloud.",
    "📲 Download apps only from official app stores.",
    "👀 Cover your webcam when not in use.",
    "🧩 Don’t reuse the same password across sites.",
    "📝 Log out of accounts when using shared devices.",
    "📶 Turn off Bluetooth when you don’t need it.",
    "⚠️ If an offer looks too good to be true, it probably is.",
    "🔑 Use a password manager to generate and store strong passwords.",
    "🔒 Change your passwords regularly, especially for banking and email.",
    "📧 Double-check sender addresses before clicking links in emails.",
    "📎 Be cautious with email attachments from unknown sources.",
    "🕵️ Hover over links before clicking to see where they really lead.",
    "📬 Use a separate email for subscriptions to reduce spam.",
    "🔍 Look for misspelled domain names — they often indicate scams.",
    "⚠️ Shortened links (bit.ly, tinyurl) can hide malicious sites. Use a preview service.",
    "🔗 Don’t click on pop-up ads offering free prizes.",
    "🚫 Never share your password, even with support agents.",
    "🚨 Watch out for fake login pages that mimic real sites.",
    "📲 Update your phone’s OS and apps regularly.",
    "🚫 Don’t install apps from unofficial sources or random APK files.",
    "🔋 Avoid charging your phone on unknown public USB ports.",
    "📴 Turn off Wi-Fi when not in use (keep this separate if you want it distinct from Bluetooth).",
    "💻 Keep antivirus and anti-malware software updated.",
    "🛠️ Install software only from trusted official websites.",
    "⏫ Regularly update your operating system patches.",
    "🔐 Encrypt sensitive files before sending them.",
    "🏦 Always type your bank’s web address manually, never click from email.",
    "💳 Use virtual cards for online shopping when possible.",
    "🚫 Avoid saving card details on random websites.",
    "📲 Set up SMS or email alerts for all banking transactions.",
    "🔒 Always log out of accounts when using public computers.",
    "🧾 Shred old documents with personal info before discarding.",
    "📱 Enable biometric authentication (fingerprint/face ID) where possible.",
    "🚨 Don’t ignore security warnings from browsers or apps.",
    "🔄 Rotate your security questions — don’t always use the same ones.",
    "🤔 Choose security answers that aren’t easily guessed or found online.",
    "🛑 Don’t overshare personal info on social media — attackers use it for phishing.",
    "🧑‍💻 Separate work and personal accounts/devices for better security.",
    "🌍 Use a VPN when browsing on public or shared networks.",
    "💡 Disable auto-fill for passwords in browsers.",
    "📵 Turn off location services when not needed.",
    "🔍 Regularly review which devices are logged into your accounts.",
    "📲 Enable remote wipe on your smartphone in case it’s lost or stolen.",
    "💳 Use credit cards instead of debit cards online for safer transactions.",
    "🧑‍🤝‍🧑 Educate your family or team about phishing scams.",
    "📥 Don’t click unsubscribe links in suspicious emails — it may confirm your address.",
    "🛡️ Add a PIN or password lock to your SIM card.",
    "🔗 Use different browsers for sensitive vs. casual browsing.",
    "👀 Regularly check your browser’s saved passwords list.",
    "🛠️ Disable macros in Office files unless absolutely needed.",
    "📧 Use disposable emails for trials, downloads, or freebies.",
    "📲 Keep Bluetooth hidden, not discoverable, when enabled.",
    "📡 Turn off NFC when not in use to prevent unwanted scans.",
    "🕵️ Check URLs for HTTPS before entering sensitive info.",
    "🔐 Encrypt your home Wi-Fi with WPA3 (or WPA2 if WPA3 isn’t available).",
    "🏠 Change your router’s default admin username and password.",
    "📡 Regularly update your Wi-Fi router firmware.",
    "📞 Be cautious of unsolicited phone calls asking for info.",
    "🚫 Never share one-time passwords (OTPs) over the phone.",
    "📤 Avoid uploading personal IDs to random websites.",
    "🔄 Use different usernames across platforms when possible.",
    "🕹️ Secure your gaming accounts — they are often targeted.",
    "🛒 Stick to trusted e-commerce sites for purchases.",
    "📦 Track deliveries using official courier apps, not random links.",
    "🧾 Review app privacy policies to see what data they collect.",
    "👁️ Periodically check which apps have camera/microphone access.",
    "🔌 Unplug external drives when not in use to avoid malware.",
    "📧 Report suspicious phishing emails instead of just deleting them.",
    "🧑‍💻 Don’t use the same password reset questions across sites.",
    "⏱️ Set devices to auto-lock after short periods of inactivity.",
    "🖥️ Don’t store passwords in Word/Excel files without encryption.",
    "📋 Avoid copy-pasting passwords on shared devices.",
    "🔗 Bookmark important websites instead of typing them in each time.",
    "📲 Enable push notifications for unusual login attempts.",
    "💳 Never give card details over email or chat.",
    "🚗 Be cautious when connecting devices in rental cars or public kiosks.",
    "📶 Regularly audit devices connected to your Wi-Fi network.",
    "⚙️ Turn off “remember me” on shared or public devices.",
    "🔒 Protect USB drives with encryption software.",
    "📱 Use different lockscreen passwords for different devices.",
    "🖥️ Disable auto-run for external USB/CD drives.",
    "🚨 Be careful of fake antivirus pop-ups — they may install malware.",
    "📧 Never reply to suspicious emails, even to say “stop”.",
    "🔑 Create unique passphrases instead of single words for better security.",
    "💬 Watch out for suspicious links in WhatsApp/Telegram groups.",
    "🔐 Always sign out of accounts in shared browsers.",
    "🛑 Don’t use your main email for job boards or public resumes.",
    "🔍 Search your name online occasionally to spot leaked info.",
    "👤 Use aliases online when you don’t need your real identity.",
    "📦 Be wary of “free” software — it may include hidden malware.",
    "🕵️ Be cautious with QR codes in public — they can be malicious.",
    "🔒 Protect your backups with encryption and strong passwords.",
    "📱 Don’t jailbreak/root your phone — it weakens security.",
    "🚫 Avoid downloading cracked or pirated software.",
    "🔎 Verify charity donation sites before giving money.",
    "🛡️ Review browser extensions — remove ones you don’t use.",
    "🖥️ Don’t leave sensitive files in your downloads folder.",
    "📊 Watch out for fake investment websites or apps.",
    "🛑 Be skeptical of job offers that request upfront fees.",
    "📱 Turn off predictive text if it learns sensitive info.",
    "🔐 Use a secure notes app instead of writing down passwords.",
    "💼 Encrypt USBs and drives before traveling internationally.",
    "🔍 Check email headers to confirm sender authenticity.",
    "📲 Only allow notifications from trusted apps.",
    "🛠️ Keep IoT devices (like smart cameras) updated.",
    "🏡 Change default usernames/passwords on smart home gadgets.",
    "📡 Put IoT devices on a separate Wi-Fi network when possible.",
    "👩‍👩‍👧 Talk to kids about online safety early.",
    "🛑 Don’t post travel details in real-time on social media.",
    "📷 Disable geotagging on photos you upload online.",
    "🔍 Audit your cloud storage for sensitive or old files.",
    "📧 Enable spam filters in your email account.",
    "📲 Lock messaging apps with an extra passcode.",
    "🛡️ Don’t accept friend requests from strangers on social media.",
    "🖥️ Avoid using outdated operating systems no longer supported.",
    "📉 Regularly review your credit report for suspicious activity.",
    "🚫 Avoid clicking links sent through SMS from unknown numbers.",
    "🧑‍💻 If you suspect you’ve been hacked, change passwords immediately.",
    "🛡️ Set up alerts for failed login attempts on your accounts.",
    "📱 Use separate devices for work and personal use if possible.",
    "🔍 Verify sellers before making P2P marketplace purchases.",
    "💳 Use transaction limits or secondary accounts for online shopping.",
    "🛠️ Clear your downloads folder regularly to avoid clutter/malware.",
    "📲 Set up automatic backups for your phone and PC.",
]

unused_tips = tips_pool.copy()


def tip(update, context: CallbackContext) -> None:
    global unused_tips

    # Reset if all tips are used
    if not unused_tips:
        unused_tips = tips_pool.copy()

    # Pick and remove a random tip
    chosen_tip = random.choice(unused_tips)
    unused_tips.remove(chosen_tip)

    update.message.reply_text(chosen_tip)


def about(update: Update, context: CallbackContext) -> None:
    #About the SecGuard bot
    update.message.reply_text(
        "🔐 *SecGuard* is your digital security buddy.\n\n"
        "It helps you stay safe online by sharing practical cybersecurity tips.\n"
        "🚀 Built to keep you aware, protected, and one step ahead of cyber threats! \n\n"
        "Created by Abdulafeez Adeniyi",
        parse_mode="Markdown")


def check_with_google_safebrowsing(url: str) -> str:
    """Check a URL using Google Safe Browsing API."""
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

    payload = {
        "client": {
            "clientId": "your-bot-name",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{
                "url": url
            }],
        },
    }

    try:
        r = requests.post(api_url, json=payload, timeout=5)
        r.raise_for_status()
        result = r.json()

        if "matches" in result:
            return "❌ Google Safe Browsing flagged this as dangerous!"
        else:
            return "✅ Google Safe Browsing found no threats."
    except Exception as e:
        return f"⚠️ Could not connect to Safe Browsing API: {e}"


def check_link(update: Update, context: CallbackContext) -> None:
    """Check if a URL looks safe or suspicious with deeper analysis."""

    if not context.args:
        update.message.reply_text(
            "❗ Please provide a URL. Example: /checklink https://example.com")
        return

    urls = context.args
    responses = []

    for url in urls:
        url = url.strip()

        if not validators.url(url):
            responses.append(f"❌ `{url}` is not a valid URL.")
            continue

        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        warnings = []
        score = 0

        # Suspicious keywords
        suspicious_keywords = [
            'login', 'verify', 'secure', 'update', 'banking', 'account'
        ]
        if any(word in url.lower() for word in suspicious_keywords):
            warnings.append("⚠️ Contains phishing-related keywords.")
            score += 2

        # Strange domain endings
        bad_tlds = ['xyz', 'top', 'tk', 'club', 'info']
        if ext.suffix in bad_tlds:
            warnings.append(f"⚠️ Suspicious domain ending: .{ext.suffix}")
            score += 2

        # IP instead of domain
        if ext.domain.isdigit():
            warnings.append("⚠️ Uses IP address instead of domain.")
            score += 2

        # Very long URL
        if len(url) > 100:
            warnings.append("⚠️ Very long URL (could be hiding something).")
            score += 1

        # Punycode check
        try:
            decoded = idna.decode(ext.domain)
            if decoded != ext.domain:
                warnings.append("⚠️ Punycode detected (possible fake domain).")
                score += 3
        except idna.IDNAError:
            pass

        # Try to connect (HEAD request)
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            status = r.status_code
            if status >= 400:
                warnings.append(f"⚠️ Site returned error code {status}.")
                score += 1
        except requests.exceptions.RequestException:
            warnings.append("⚠️ Site not reachable.")
            score += 2

        # Safe domains whitelist
        safe_domains = [
            "google.com", "facebook.com", "twitter.com", "whatsapp.com",
            "bankofamerica.com", "microsoft.com"
        ]
        if domain in safe_domains:
            result = "✅ Recognized safe domain."
        else:
            if score >= 4:
                result = "❌ Risky URL! Avoid clicking."
            elif score >= 2:
                result = "⚠️ Suspicious. Be cautious."
            else:
                result = "ℹ️ No obvious issues, but always stay alert."

        # Build response
        response = f"🔗 URL: {url}\n🌐 Domain: {domain}\n{result}"
        if warnings:
            response += "\n" + "\n".join(warnings)

        # Add Google Safe Browsing result
        google_result = check_with_google_safebrowsing(url)
        response += f"\n{google_result}"

        responses.append(response)

    update.message.reply_text("\n\n".join(responses), parse_mode="Markdown")


#error handler
def error_handler(update: object, context: CallbackContext) -> None:
    """Log errors caused by Updates."""
    logger.error(msg="Exception while handling an update:",
                 exc_info=context.error)


# Flask web server to keep Repl alive
# -----------------------------
app: Flask = Flask('')


@app.route('/')
def home() -> str:
    return "✅ SecGuard bot is running!"


def run_flask() -> None:
    app.run(host='0.0.0.0', port=8080)


def unknown(update: Update, context: CallbackContext) -> None:
    """Handle unknown commands."""
    update.message.reply_text(
        "❓ Sorry, I didn’t understand that command. Try /tip or /about or /checklink."
    )


def echo(update: Update, context: CallbackContext) -> None:
    """Echo back any text that is not a command."""
    update.message.reply_text(
        "🤖 Got it! Try /tip for a safety tip, /about to know more about SecGuard or /checklink to check if url is safe."
    )


# --- Main bot runner ---
def main():
    # Start Flask web server in a separate thread
    t: Thread = Thread(target=run_flask)
    t.start()

    #telegram bot set up
    updater = Updater(BOT_TOKEN, use_context=True)
    dp: Dispatcher = updater.dispatcher  # type: ignore

    # Register handlers
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("tip", tip))
    dp.add_handler(CommandHandler("about", about))
    dp.add_handler(CommandHandler("checklink", check_link))
    dp.add_handler(MessageHandler(Filters.command, unknown))
    dp.add_error_handler(error_handler)
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    # Start polling Telegram for updates
    updater.start_polling()
    print("✅ SecGuard bot is running...")
    updater.idle()


if __name__ == "__main__":
    main()
