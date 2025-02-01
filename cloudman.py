import logging
import dns.resolver
from ping3 import ping
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import asyncio
import re
import os
import whoisdomain as whois
import signal
import sys

# Setup logging
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)
logger = logging.getLogger()

API_TOKEN = 'YOUR API_TOKEN FROM BOT FATHER'
# Store users' expected values and intervals
users = {}
expected_values = {}

# Scheduler for periodic jobs
scheduler = BackgroundScheduler()
scheduler.start()

# Function to check DNS records
def check_dns(domain, record_type):
    result = {
        'A': [],
        'TXT': [],
        'SPF': [],
        'MX': [],
        'NS': [],
        'ping': False
    }
    try:
        if record_type == "A":
            a_records = dns.resolver.resolve(domain, 'A')
            result['A'] = [ip.address for ip in a_records]
            if result['A']:
                ip_address = result['A'][0]
                result['ping'] = ping(ip_address) is not None

        elif record_type == "TXT":
            txt_records = dns.resolver.resolve(domain, 'TXT')
            result['TXT'] = [txt.to_text() for txt in txt_records]

        elif record_type == "SPF":
            txt_records = dns.resolver.resolve(domain, 'TXT')
            result['SPF'] = [txt.to_text() for txt in txt_records if 'v=spf1' in txt.to_text()]

        elif record_type == "MX":
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['MX'] = [mx.exchange.to_text() for mx in mx_records]

        elif record_type == "NS":
            ns_records = dns.resolver.resolve(domain, 'NS')
            result['NS'] = [ns.to_text() for ns in ns_records]

    except Exception as e:
        logger.error(f"Error checking DNS records for {domain} (type {record_type}): {e}")

    return result

# Function to compare results with expected values
def compare_with_expected(current_results, record_type, expected_value):
    current_value = current_results.get(record_type, [])
    if expected_value in current_value:
        return f"{record_type} record matches the expected value: {expected_value} ✅"
    else:
        return f"{record_type} record mismatch: {current_value} vs expected value: {expected_value}"

# Function to fetch WHOIS data
def fetch_whois(domain):
    try:
        d = whois.query(domain)
        if not d:
            return {"error": "WHOIS data not found for this domain."}

        return {
            "Domain Name": d.name,
            "Registrar": d.registrar,
            "Creation Date": d.creation_date,
            "Expiration Date": d.expiration_date,
            "Last Updated": d.last_updated,
            "Status": d.status,
            "Name Servers": ", ".join(d.name_servers) if d.name_servers else None,
            "Emails": ", ".join(d.emails) if d.emails else None,
            "Registrant": d.registrant,
        }
    except Exception as e:
        logger.error(f"Error fetching WHOIS for {domain}: {e}")
        return {"error": str(e)}

# Format WHOIS data for a readable response
def format_whois_data(whois_data):
    if "error" in whois_data:
        return f"Error: {whois_data['error']}"

    response = []
    for key, value in whois_data.items():
        response.append(f"{key}: {value}")
    return "\n".join(response)

# Command: /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_message = (
        "Welcome to DNS and WHOIS Checker Bot!\n\n"
        "Available commands:\n"
        "/check <domain> <record_type> --expected <expected_value> --interval <interval> - Check DNS record and compare with expected value.\n"
        "/whois <domain> --interval <interval> - Get WHOIS information and check periodically.\n"
        "/cancel - Cancel all periodic updates.\n\n"
        "Examples:\n"
        "/check example.com\n"
        "/check example.com TXT --expected example-value --interval 10M\n"
        "/whois example.com --interval 2D\n"
        "Valid intervals: 10M (10 minutes), 30M (30 minutes), 2D (2 days)\n"
    )
    await update.message.reply_text(welcome_message)

# Command: /check
async def check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    args = context.args

    # Check if domain is provided
    if len(args) < 1:
        await update.message.reply_text("Usage: /check <domain> [record_type] [--expected <expected_value>] [--interval <interval>]")
        return

    domain = args[0]
    record_type = 'A'  # Default to 'A' record
    expected_value = None
    interval = None

    # Parse optional arguments
    if len(args) > 1:
        if args[1].upper() in ['A', 'TXT', 'SPF', 'MX', 'NS']:
            record_type = args[1].upper()
        if '--expected' in args:
            expected_value = args[args.index('--expected') + 1]
        if '--interval' in args:
            interval = args[args.index('--interval') + 1]

    # Validate domain format
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        await update.message.reply_text("Invalid domain format. Please provide a valid domain (e.g., example.com).")
        return

    # Validate interval format
    interval_seconds = None
    if interval:
        if not re.match(r'^\d+[MD]$', interval):
            await update.message.reply_text("Invalid interval format. Use 10M, 30M, or 2D.")
            return
        interval_seconds = int(interval[:-1]) * (60 if interval[-1] == 'M' else 86400)

    # Store values in users dict
    users[user_id] = domain
    expected_values[user_id] = {'record_type': record_type, 'expected_value': expected_value, 'interval': interval_seconds}

    await update.message.reply_text(
        f"Checking {record_type} record for {domain}...\n"
        f"{f'Expected: {expected_value}' if expected_value else ''}\n"
        f"Interval: {interval if interval else 'One-time check'}"
    )

    # Perform DNS check
    results = check_dns(domain, record_type)
    if expected_value:
        comparison_message = compare_with_expected(results, record_type, expected_value)
        await update.message.reply_text(comparison_message)
    else:
        result_message = f"{record_type} record for {domain}:\n{results.get(record_type, 'No record found')}"
        await update.message.reply_text(result_message)

    # Schedule periodic checks if interval is provided
    if interval_seconds:
        scheduler.add_job(
            lambda: asyncio.run(periodic_dns_check(user_id)),
            IntervalTrigger(seconds=interval_seconds)
        )

# Command: /whois
async def whois_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    args = context.args

    if len(args) < 1:
        await update.message.reply_text("Usage: /whois <domain> --interval <interval>")
        return

    domain = args[0]

    interval = None
    if '--interval' in args:
        interval = args[args.index('--interval') + 1]
        if not re.match(r'^\d+[MD]$', interval):
            await update.message.reply_text("Invalid interval format. Use 10M, 30M, or 2D.")
            return

    interval_seconds = None
    if interval:
        interval_seconds = int(interval[:-1]) * (60 if interval[-1] == 'M' else 86400)

    if interval_seconds and interval_seconds < 86400:
        await update.message.reply_text("WHOIS data rarely changes frequently. Consider using an interval of at least 1 day (1D).")

    users[user_id] = domain

    await update.message.reply_text(f"Fetching WHOIS information for {domain}...\nInterval: {interval if interval else 'One-time check'}")

    whois_data = fetch_whois(domain)
    response = format_whois_data(whois_data)
    await update.message.reply_text(response)

    if interval_seconds:
        scheduler.add_job(lambda: asyncio.run(periodic_whois_check(user_id)), IntervalTrigger(seconds=interval_seconds))

# Periodic DNS check
async def periodic_dns_check(user_id):
    domain = users[user_id]
    record_type = expected_values[user_id]['record_type']
    expected_value = expected_values[user_id]['expected_value']

    results = check_dns(domain, record_type)
    comparison_message = compare_with_expected(results, record_type, expected_value)

    await application.bot.send_message(chat_id=user_id, text=f"Periodic DNS Check Update for {domain}:\n{comparison_message}")

# Periodic WHOIS check
async def periodic_whois_check(user_id):
    domain = users[user_id]
    whois_data = fetch_whois(domain)
    response = format_whois_data(whois_data)

    await application.bot.send_message(chat_id=user_id, text=f"Periodic WHOIS Check Update for {domain}:\n{response}")

# Command: /cancel
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id

    if user_id in users:
        scheduler.remove_all_jobs()
        del users[user_id]
        await update.message.reply_text("Updates have been canceled. You will no longer receive periodic DNS or WHOIS check updates.")
    else:
        await update.message.reply_text("You don't have any active updates to cancel.")

# Graceful shutdown handler
def shutdown(signum, frame):
    scheduler.shutdown(wait=False)
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

# Set up the bot
application = Application.builder().token(API_TOKEN).build()
application.add_handler(CommandHandler('start', start))
application.add_handler(CommandHandler('check', check))
application.add_handler(CommandHandler('whois', whois_info))
application.add_handler(CommandHandler('cancel', cancel))

if __name__ == "__main__":
    application.run_polling()
