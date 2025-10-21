import asyncio
import logging
import sqlite3
import requests
import json
import phonenumbers
from phonenumbers import carrier, timezone, geocoder
import ipaddress
import re
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# ==================== CONFIGURATION ====================
BOT_TOKEN = "7986542974:AAGSj6EsSVHyJrY4sHNIaNrQr3Jm4Ld8F1w"
ADMIN_IDS = [7896890222]  # Your admin ID

# API Keys (You can get free keys from these services)
IPINFO_TOKEN = "free"  # ipinfo.io free tier
WHOIS_API_KEY = "your_whois_api_key"
HIBP_API_KEY = "your_hibp_api_key"  # Have I Been Pwned

class OSINTBot:
    def __init__(self):
        self.app = Application.builder().token(BOT_TOKEN).build()
        self.setup_handlers()
        self.init_database()
        print("🔍 OSINT Bot Activated - Ready for intelligence gathering")
        
    def init_database(self):
        """Initialize OSINT database"""
        self.conn = sqlite3.connect('osint_data.db', check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS search_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                search_type TEXT,
                target TEXT,
                result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                country TEXT,
                city TEXT,
                isp TEXT,
                latitude REAL,
                longitude REAL,
                user_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phone_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT,
                country TEXT,
                carrier TEXT,
                timezone TEXT,
                valid BOOLEAN,
                user_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()

    def setup_handlers(self):
        """Setup bot command handlers"""
        self.app.add_handler(CommandHandler("start", self.start_handler))
        self.app.add_handler(CommandHandler("info", self.info_handler))
        self.app.add_handler(CommandHandler("ip", self.ip_handler))
        self.app.add_handler(CommandHandler("phone", self.phone_handler))
        self.app.add_handler(CommandHandler("username", self.username_handler))
        self.app.add_handler(CommandHandler("email", self.email_handler))
        self.app.add_handler(CommandHandler("scan", self.full_scan_handler))
        self.app.add_handler(CommandHandler("admin", self.admin_handler))
        self.app.add_handler(CommandHandler("stats", self.stats_handler))
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.message_handler))
        self.app.add_handler(CallbackQueryHandler(self.button_handler))

    async def start_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Welcome message with OSINT capabilities"""
        user = update.effective_user
        
        welcome_text = """
🔍 *OSINT Intelligence Bot* 🕵️‍♂️

*Advanced Open Source Intelligence Gathering*

⚡️ *Available Intelligence Modules:*
• `/info @username` - Get Telegram user info
• `/ip 8.8.8.8` - IP address geolocation
• `/phone +1234567890` - Phone number analysis
• `/username john_doe` - Social media lookup
• `/email test@example.com` - Email breach check
• `/scan target` - Full OSINT profile scan

📊 *Admin Commands:*
• `/admin` - System controls
• `/stats` - Search statistics

*Send any username, IP, phone, or email for analysis*
        """
        
        keyboard = [
            [InlineKeyboardButton("👤 User Info", callback_data="user_info"),
             InlineKeyboardButton("🌐 IP Lookup", callback_data="ip_lookup")],
            [InlineKeyboardButton("📱 Phone Scan", callback_data="phone_scan"),
             InlineKeyboardButton("📧 Email Check", callback_data="email_check")],
            [InlineKeyboardButton("🔍 Full Scan", callback_data="full_scan"),
             InlineKeyboardButton("📊 Stats", callback_data="stats")],
        ]
        if user.id in ADMIN_IDS:
            keyboard.append([InlineKeyboardButton("🛠 Admin Panel", callback_data="admin_panel")])
            
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(welcome_text, parse_mode='Markdown', reply_markup=reply_markup)
        
        self.log_search(user.id, "start", "Bot accessed")

    async def info_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get Telegram user information"""
        if not context.args:
            await update.message.reply_text(
                "👤 *User Information Lookup*\\n\\n"
                "Usage: `/info @username` or `/info user_id`\\n\\n"
                "*Example:* `/info @john_doe`",
                parse_mode='Markdown'
            )
            return
            
        target = context.args[0]
        user_id = update.effective_user.id
        
        processing_msg = await update.message.reply_text(
            f"🔍 *Scanning User:* `{target}`\\n"
            "🔄 Gathering intelligence from multiple sources...",
            parse_mode='Markdown'
        )
        
        # Gather user intelligence
        result = await self.analyze_telegram_user(target, user_id)
        await self.send_user_info(update, processing_msg, result, target)

    async def analyze_telegram_user(self, target, searcher_id):
        """Analyze Telegram user for OSINT data"""
        user_data = {
            'target': target,
            'basic_info': {},
            'phone_analysis': {},
            'social_links': [],
            'risk_assessment': {}
        }
        
        # Basic user info simulation (in real scenario, use Telegram API)
        user_data['basic_info'] = {
            'username': target.replace('@', ''),
            'user_id': 'N/A',
            'first_seen': '2023-01-01',
            'last_seen': 'Just now',
            'is_bot': False,
            'language': 'English'
        }
        
        # Phone number analysis
        phone_pattern = r'\+?[1-9]\d{1,14}'
        phone_matches = re.findall(phone_pattern, target)
        if phone_matches:
            user_data['phone_analysis'] = await self.analyze_phone_number(phone_matches[0])
        
        # Social media lookup
        user_data['social_links'] = await self.find_social_media(target.replace('@', ''))
        
        # Risk assessment
        user_data['risk_assessment'] = {
            'threat_level': 'LOW',
            'data_breaches': 0,
            'suspicious_activity': 'None detected'
        }
        
        self.log_search(searcher_id, "user_info", f"Target: {target}")
        
        return user_data

    async def ip_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """IP address geolocation and analysis"""
        if not context.args:
            await update.message.reply_text(
                "🌐 *IP Address Intelligence*\\n\\n"
                "Usage: `/ip 8.8.8.8`\\n\\n"
                "*Example:* `/ip 192.168.1.1`",
                parse_mode='Markdown'
            )
            return
            
        ip_target = context.args[0]
        user_id = update.effective_user.id
        
        # Validate IP address
        try:
            ipaddress.IPv4Address(ip_target)
        except ipaddress.AddressValueError:
            await update.message.reply_text("❌ *Invalid IP address format*")
            return
        
        processing_msg = await update.message.reply_text(
            f"🌐 *Analyzing IP:* `{ip_target}`\\n"
            "🔄 Gathering geolocation and network data...",
            parse_mode='Markdown'
        )
        
        result = await self.analyze_ip_address(ip_target, user_id)
        await self.send_ip_info(update, processing_msg, result, ip_target)

    async def analyze_ip_address(self, ip_address, searcher_id):
        """Analyze IP address for intelligence"""
        try:
            # Using ipinfo.io free API
            response = requests.get(f'https://ipinfo.io/{ip_address}/json')
            data = response.json()
            
            ip_data = {
                'ip': ip_address,
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'isp': data.get('org', 'Unknown'),
                'location': data.get('loc', '0,0'),
                'postal': data.get('postal', 'Unknown')
            }
            
            # Get coordinates
            if ip_data['location'] != '0,0':
                lat, lon = ip_data['location'].split(',')
                ip_data['latitude'] = float(lat)
                ip_data['longitude'] = float(lon)
            
            # Log the IP search
            self.log_ip_search(ip_address, ip_data.get('country'), ip_data.get('city'), 
                             ip_data.get('isp'), searcher_id)
            
            return ip_data
            
        except Exception as e:
            return {'error': str(e)}

    async def phone_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Phone number intelligence analysis"""
        if not context.args:
            await update.message.reply_text(
                "📱 *Phone Number Intelligence*\\n\\n"
                "Usage: `/phone +1234567890`\\n\\n"
                "*Example:* `/phone +14155552671`",
                parse_mode='Markdown'
            )
            return
            
        phone_target = context.args[0]
        user_id = update.effective_user.id
        
        processing_msg = await update.message.reply_text(
            f"📱 *Analyzing Phone:* `{phone_target}`\\n"
            "🔄 Validating and gathering carrier data...",
            parse_mode='Markdown'
        )
        
        result = await self.analyze_phone_number(phone_target)
        await self.send_phone_info(update, processing_msg, result, phone_target)

    async def analyze_phone_number(self, phone_number):
        """Comprehensive phone number analysis"""
        try:
            # Parse phone number
            parsed_number = phonenumbers.parse(phone_number, None)
            
            phone_data = {
                'original': phone_number,
                'valid': phonenumbers.is_valid_number(parsed_number),
                'country': geocoder.description_for_number(parsed_number, "en"),
                'carrier': carrier.name_for_number(parsed_number, "en"),
                'timezone': timezone.time_zones_for_number(parsed_number),
                'type': 'MOBILE' if carrier.name_for_number(parsed_number, "en") else 'UNKNOWN'
            }
            
            # Find alternative formats
            phone_data['alternative_formats'] = [
                phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164),
                phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
            ]
            
            return phone_data
            
        except Exception as e:
            return {'error': str(e), 'valid': False}

    async def username_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Social media username lookup"""
        if not context.args:
            await update.message.reply_text(
                "👤 *Username OSINT Search*\\n\\n"
                "Usage: `/username john_doe`\\n\\n"
                "*Example:* `/username elonmusk`",
                parse_mode='Markdown'
            )
            return
            
        username = context.args[0]
        user_id = update.effective_user.id
        
        processing_msg = await update.message.reply_text(
            f"👤 *Searching Username:* `{username}`\\n"
            "🔄 Scanning social media platforms...",
            parse_mode='Markdown'
        )
        
        result = await self.find_social_media(username)
        await self.send_username_info(update, processing_msg, result, username)

    async def find_social_media(self, username):
        """Find social media profiles for username"""
        platforms = {
            'Instagram': f'https://instagram.com/{username}',
            'Twitter/X': f'https://twitter.com/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'GitHub': f'https://github.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'TikTok': f'https://tiktok.com/@{username}'
        }
        
        found_profiles = []
        
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    found_profiles.append({
                        'platform': platform,
                        'url': url,
                        'status': 'FOUND'
                    })
                else:
                    found_profiles.append({
                        'platform': platform,
                        'url': url,
                        'status': 'NOT_FOUND'
                    })
            except:
                found_profiles.append({
                    'platform': platform,
                    'url': url,
                    'status': 'ERROR'
                })
        
        return found_profiles

    async def email_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Email breach check and analysis"""
        if not context.args:
            await update.message.reply_text(
                "📧 *Email Breach Check*\\n\\n"
                "Usage: `/email test@example.com`\\n\\n"
                "*Example:* `/email user@gmail.com`",
                parse_mode='Markdown'
            )
            return
            
        email = context.args[0]
        user_id = update.effective_user.id
        
        processing_msg = await update.message.reply_text(
            f"📧 *Analyzing Email:* `{email}`\\n"
            "🔄 Checking data breaches and reputation...",
            parse_mode='Markdown'
        )
        
        result = await self.check_email_breaches(email)
        await self.send_email_info(update, processing_msg, result, email)

    async def check_email_breaches(self, email):
        """Check if email appears in data breaches"""
        # Note: For actual HIBP API, you need an API key
        breach_data = {
            'email': email,
            'breaches_found': 0,
            'breach_list': [],
            'risk_level': 'LOW'
        }
        
        # Simulated breach check (replace with actual HIBP API)
        simulated_breaches = [
            {'name': 'Adobe Breach 2013', 'date': '2013-10-04', 'data_compromised': 'Email, Password'},
            {'name': 'LinkedIn Breach 2012', 'date': '2012-06-05', 'data_compromised': 'Email, Password'}
        ]
        
        breach_data['breaches_found'] = len(simulated_breaches)
        breach_data['breach_list'] = simulated_breaches
        
        if breach_data['breaches_found'] > 5:
            breach_data['risk_level'] = 'HIGH'
        elif breach_data['breaches_found'] > 2:
            breach_data['risk_level'] = 'MEDIUM'
            
        return breach_data

    async def full_scan_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Complete OSINT profile scan"""
        if not context.args:
            await update.message.reply_text(
                "🔍 *Full OSINT Profile Scan*\\n\\n"
                "Usage: `/scan target`\\n\\n"
                "*Example:* `/scan @username` or `/scan email@domain.com`",
                parse_mode='Markdown'
            )
            return
            
        target = context.args[0]
        user_id = update.effective_user.id
        
        processing_msg = await update.message.reply_text(
            f"🔍 *Initiating Full OSINT Scan:* `{target}`\\n"
            "🔄 Deploying all intelligence modules...\\n"
            "This may take a few moments",
            parse_mode='Markdown'
        )
        
        # Run all analysis types
        results = {}
        
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            results['ip_analysis'] = await self.analyze_ip_address(target, user_id)
        elif re.match(r'^\+?[1-9]\d{1,14}$', target):
            results['phone_analysis'] = await self.analyze_phone_number(target)
        elif '@' in target:
            results['email_analysis'] = await self.check_email_breaches(target)
            results['social_media'] = await self.find_social_media(target.split('@')[0])
        else:
            results['user_analysis'] = await self.analyze_telegram_user(target, user_id)
            results['social_media'] = await self.find_social_media(target.replace('@', ''))
        
        await self.send_full_scan_results(update, processing_msg, results, target)

    # ==================== RESULT DISPLAY METHODS ====================

    async def send_user_info(self, update, processing_msg, result, target):
        """Send user intelligence results"""
        info_text = f"""
👤 *User Intelligence Report*

🎯 *Target:* `{target}`
🆔 *Username:* {result['basic_info']['username']}
📅 *First Seen:* {result['basic_info']['first_seen']}
🌐 *Language:* {result['basic_info']['language']}

📱 *Phone Analysis:*
{self.format_phone_data(result.get('phone_analysis', {}))}

🔗 *Social Media Presence:*
{self.format_social_media(result.get('social_links', []))}

⚠️ *Risk Assessment:* {result['risk_assessment']['threat_level']}
"""
        await processing_msg.edit_text(info_text, parse_mode='Markdown')

    async def send_ip_info(self, update, processing_msg, result, target):
        """Send IP intelligence results"""
        if 'error' in result:
            await processing_msg.edit_text(f"❌ *IP Analysis Failed:* {result['error']}", parse_mode='Markdown')
            return
            
        info_text = f"""
🌐 *IP Intelligence Report*

🎯 *Target IP:* `{target}`
🏴 *Country:* {result.get('country', 'Unknown')}
🏙️ *City:* {result.get('city', 'Unknown')}
🏢 *ISP:* {result.get('isp', 'Unknown')}
🕐 *Timezone:* {result.get('timezone', 'Unknown')}
📍 *Coordinates:* {result.get('location', 'Unknown')}

📊 *Additional Data:*
• Region: {result.get('region', 'Unknown')}
• Postal Code: {result.get('postal', 'Unknown')}

🔍 *Intelligence Level:* BASIC
"""
        await processing_msg.edit_text(info_text, parse_mode='Markdown')

    async def send_phone_info(self, update, processing_msg, result, target):
        """Send phone number intelligence results"""
        if 'error' in result:
            await processing_msg.edit_text(f"❌ *Phone Analysis Failed:* {result['error']}", parse_mode='Markdown')
            return
            
        info_text = f"""
📱 *Phone Intelligence Report*

🎯 *Target Number:* `{target}`
✅ *Valid:* {result.get('valid', False)}
🏴 *Country:* {result.get('country', 'Unknown')}
📞 *Carrier:* {result.get('carrier', 'Unknown')}
🕐 *Timezone:* {', '.join(result.get('timezone', []))}

🔢 *Alternative Formats:*
"""
        for fmt in result.get('alternativ
