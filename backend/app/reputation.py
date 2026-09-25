"""
Domain reputation layer (runs AFTER the ML model).

Problem it solves: the model only sees URL text, so a real login page such
as login.microsoftonline.com/.../authorize?client_id=... looks exactly like
a phishing login page. What actually separates them is WHO OWNS THE DOMAIN,
which URL text cannot show.

Rule: if the URL's registered domain is among the most popular websites in
the Tranco list (research-grade ranking, https://tranco-list.eu), a
"phishing" verdict is capped at "suspicious" - the user is still warned,
but a well-established site is never accused outright. It never turns a
result into "legitimate"; that is only the curated allowlist's job.

Popular platforms where ANYONE can publish content (free hosting, cloud
storage, IPFS gateways, form builders...) are excluded, because attackers
host phishing there. Two mechanisms:
  1. tldextract with the Public Suffix List's PRIVATE section: e.g.
     evil.web.app / evil.github.io / evil.blogspot.com resolve to their own
     registered domain, which is not ranked, so they get no reputation.
  2. HOSTING_PLATFORMS below, for platforms not on the Public Suffix List
     (found by checking which popular domains host PhiUSIIL / OpenPhish
     phishing).
"""
import csv
import os
from urllib.parse import urlparse

import joblib
import tldextract

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.join(_HERE, "..", "..")
_CACHE = os.path.join(_ROOT, "outputs", "tranco_rank.joblib")
_TRANCO_CSV = os.path.join(_ROOT, "top-1m.csv")

# Domains ranked within this many positions count as "reputable".
# Chosen with backend/tests/realworld_eval.py (see the report there).
MAX_RANK = 250_000
# Stricter cut-off for the HTTP rule (ml_state.classify_vec), which can turn
# "suspicious" into "legitimate": phishing on 100k-250k ranked domains was
# mostly free hosting, while ~99% of legit http pages tested rank <= 100k.
HTTP_RULE_MAX_RANK = 100_000

# Offline: uses tldextract's bundled Public Suffix List snapshot (no
# network call at runtime).
_extract_private = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_extract_icann = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

HOSTING_PLATFORMS = {
    # site builders / free hosting
    "weebly.com", "weeblysite.com", "wixsite.com", "wix.com", "square.site",
    "godaddysites.com", "webflow.io", "carrd.co", "strikingly.com",
    "jimdosite.com", "site123.me", "mystrikingly.com", "yolasite.com",
    "000webhostapp.com", "000webhost.com", "wordpress.com", "blogger.com",
    "tumblr.com", "notion.site", "gitbook.io", "framer.app", "framer.website",
    "repl.co", "replit.app", "replit.dev", "glitch.me", "pantheonsite.io",
    "xsph.ru", "tw1.ru", "regruhosting.ru", "cprapid.com", "hostingersite.com",
    "infinityfreeapp.com", "rf.gd", "epizy.com", "byethost.com",
    # cloud / serverless / object storage
    "workers.dev", "pages.dev", "r2.dev", "amazonaws.com", "cloudfront.net",
    "windows.net", "azurewebsites.net", "azureedge.net", "web.core.windows.net",
    "googleapis.com", "appspot.com", "firebaseapp.com", "web.app",
    "netlify.app", "vercel.app", "onrender.com", "herokuapp.com",
    "github.io", "gitlab.io", "surge.sh", "fly.dev", "railway.app",
    "digitaloceanspaces.com", "backblazeb2.com", "wasabisys.com",
    # IPFS / decentralised gateways
    "ipfs.io", "dweb.link", "cf-ipfs.com", "pinata.cloud", "w3s.link",
    "fleek.co", "4everland.io", "nftstorage.link",
    # file sharing / forms / docs / link-in-bio / short links
    "dropbox.com", "dropboxusercontent.com", "box.com", "mediafire.com",
    "wetransfer.com", "sharepoint.com", "onedrive.live.com", "1drv.ms",
    "forms.gle", "jotform.com", "typeform.com", "formstack.com",
    "linktr.ee", "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "ow.ly", "rb.gy", "qrco.de",
    # found on popular domains in PhiUSIIL phishing (sample, top-250k check)
    "webwave.dev", "myportfolio.com", "infura-ipfs.io", "myqcloud.com",
    "aliyuncs.com", "swtest.ru", "usrfiles.com", "publicvm.com", "start.page",
    "s.id", "myhuaweicloud.com", "work.gd", "webcindario.com", "temp-site.link",
    "cloudwaysapps.com", "codeanyapp.com", "short.gy", "selcdn.ru",
    "oraclecloud.com", "beget.tech", "cloudclusters.net", "arweave.net",
    "free.fr", "ic0.app", "zzz.com.ua", "urlz.fr", "myftpupload.com",
    "secureserver.net", "wpengine.com", "tmweb.ru", "1gb.ru", "dynadot.com",
    "crazydomains.com", "bio.site", "preview-domain.com",
    # dynamic DNS / tunnels (incl. ChangeIP free domains)
    "itsaol.com", "zzux.com", "yourtrap.com", "longmusic.com", "2waky.com",
    "duckdns.org", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com",
    "serveo.net", "no-ip.com", "ddns.net", "hopto.org", "zapto.org",
    # found in 2024-25 Phishing.Database feeds: popular domains listed with
    # many different phishing subdomains (notebooks/harvest_phish_feeds.py)
    "appdomain.cloud", "filesusr.com", "mybluehost.me", "mybluehostin.me",
    "teachable.com", "thinkific.com", "atwebpages.com", "page.link", "app.link",
    "serv00.net", "ct8.pl", "temporary.site", "temporary.link", "studio.site",
    "easy.co", "b-cdn.net", "liveblog365.com", "lovestoblog.com", "jimdofree.com",
    "moonfruit.com", "inmotionhosting.com", "softlayer.net", "nxcli.net", "nxcli.io",
    "flywheelsites.com", "codesandbox.io", "tripod.com", "angelfire.com", "sibforms.com",
    "kinsta.cloud", "googleusercontent.com", "tiiny.site", "edgeone.app", "edgeone.dev",
    "contaboserver.net", "mytemp.website", "unaux.com", "kesug.com", "wuaze.com",
    "free.nf", "42web.io", "great-site.net", "neocities.org", "webnode.page",
    "webnode.com", "webnode.es", "sg-host.com", "goorm.io", "stackstaging.com",
    "hs-sites.com", "hs-sites-eu1.com", "netsolhost.com", "somee.com", "cloudlets.zone",
    "sitey.me", "ucoz.net", "sslip.io", "nip.io", "wasmer.app", "koyeb.app",
    "webador.com", "netsons.org", "16mb.com", "esy.es", "hol.es", "my-free.website",
    "mobirisesite.com", "editmysite.com", "business.site", "multiscreensite.com",
    "powerappsportals.com", "bitrix24.site", "hstgr.cloud", "onrocket.site",
    "web-hosting.com", "webhostbox.net", "x10host.com", "x10.mx", "atspace.com",
    "orgfree.com", "tilda.ws", "mystagingwebsite.com", "mywebsitetransfer.com",
    "websitetestlink.com", "shopifypreview.com", "eth.limo", "icp0.io", "zapier.app",
    "azurecontainerapps.io", "unifiedlayer.com", "mysecurecloudhost.com", "fc2.com",
    "over-blog.com", "webs.com", "cargo.site", "mypinata.cloud", "upcloudobjects.com",
    "selstorage.ru", "bget.ru", "nichost.ru", "at.ua", "1gb.ua", "cba.pl",
    "dothome.co.kr", "xsrv.jp", "xdomain.jp", "mixh.jp", "peraichi.com",
    "meusitehostgator.com.br", "hospedagemdesites.ws", "lojaintegrada.com.br",
    "crabdance.com", "zyns.com", "dynamic-dns.net", "ydns.eu", "dns05.com", "dns04.com",
    "serveuser.com", "serveusers.com", "dvrlists.com", "dnset.com", "myddns.me",
    "myddns.com", "ddns.us", "ddnss.eu", "ddns.info", "ddns.ms", "ddns.mobi",
    "linkpc.net", "mooo.com", "us.to", "my.to", "odns.fr", "ignorelist.com",
    "strangled.net", "dynssl.com", "freeddns.com", "anondns.net", "abrdns.com",
    "changeip.co", "changeip.us", "chickenkiller.com", "jumpingcrab.com",
    "twilightparadox.com", "sieraddns.com", "f3322.net", "v6.rocks", "wikaba.com",
    "otzo.com", "x24hr.com", "ocry.com", "ezua.com", "4dq.com", "25u.com", "jkub.com",
    "itemdb.com", "misecure.com", "jetos.com", "ourhobby.com", "my03.com",
    "onedumb.com", "dumb1.com", "qpoe.com", "4pu.com", "myz.info", "freetcp.com",
    "mrbasic.com", "mrbonus.com", "qhigh.com", "mefound.com", "ftp1.biz", "ikwb.com",
    "vizvaz.com", "faqserv.com", "fartit.com", "instanthq.com", "acmetoy.com",
    "justdied.com", "almostmy.com", "jungleheart.com", "mrface.com", "mynetav.com",
    "onmypc.net", "ftp.sh", "youdontcare.com", "ueuo.com", "tftpd.net", "servconfig.com",
    "run.place", "lflink.com", "lflinkup.com", "myftp.info", "easterndns.com",
    # found by simulating the HTTP rule (ml_state.classify_vec) on all
    # PhiUSIIL + 2024-25 feed http:// phishing: platforms / shorteners /
    # dynamic DNS whose user subdomains or links would otherwise count as
    # reputable
    "bitly.ws", "bitly.cx", "bitly.com", "bit.do", "lnk.to", "fanlink.to", "me-qr.com",
    "qr1.be", "qrcodes.pro", "uqr.to", "flowcode.com", "surl.li", "cutt.us", "alturl.com",
    "tiny.cc", "tiny.one", "tiny.us", "gg.gg", "ppt.cc", "jii.li", "cort.as", "lihi1.com",
    "abre.ai", "mssg.me", "hopp.bio", "user.fm", "questionpro.com", "simplybook.it",
    "mjt.lu", "shoprenter.hu", "versacommerce.de", "home.pl", "smarthost.pl", "webd.pl",
    "myhostpoint.ch", "funpic.de", "kilu.de", "hys.cz", "8u.cz", "clan.su", "ucoz.ru",
    "ucoz.com", "narod.ru", "do.am", "axc.nl", "ovh.net", "binero.se", "blogsky.com",
    "flazio.com", "format.com", "atw.hu", "uw.hu", "eoldal.hu", "chez.com", "piczo.com",
    "t35.com", "biz.nf", "fr.nf", "es.tl", "tr.gg", "eu.cc", "us.cc", "webmo.fr",
    "westnet.com.au", "seetong.com", "hubside.fr", "univer.se", "phpnet.us", "e-kei.pl",
    "bee.pl", "5v.pl", "vot.pl", "7m.pl", "dx.am", "cu.ma", "ukit.me", "ct.ws", "x10.bz",
    "whf.bz", "22web.org", "myfreesites.net", "cleansite.us", "mycpanel.rs", "ferozo.com",
    "webservis.ru", "h1n.ru", "webador.de", "webnode.be", "finance.blog", "code.blog",
    "mysch.gr", "dtdns.com", "ddo.jp", "ddnss.ch", "ddns.com.br",
    "dyndns.dk", "dns1.us", "dns2.us", "dnsrd.com", "ns01.us", "ns01.info", "kro.kr",
    "o-r.kr", "p-e.kr", "vicp.net", "3322.net", "3322.org", "f3322.org", "oray.com",
    "ygto.com", "xxuz.com", "6f.sk",
}

# Specific subdomains of otherwise-reputable companies where users publish
# content (docs.google.com forms, sites.google.com pages, ...).
HOSTING_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "script.google.com",
    "storage.cloud.google.com", "forms.office.com", "forms.microsoft.com",
    "onedrive.live.com", "1drv.ms", "sway.office.com", "gamma.app", "sites.sch.gr",
}


def is_user_content_host(url: str) -> bool:
    """True for hosts where anyone can publish pages (platform domains and
    user-content subdomains of big companies). Used by the allowlist too,
    so "google.com is trusted" never extends to sites.google.com pages."""
    host = _host(url)
    if not host:
        return False
    icann_reg = _extract_icann(host).top_domain_under_public_suffix
    private_reg = _extract_private(host).top_domain_under_public_suffix
    return (
        private_reg != icann_reg
        or icann_reg in HOSTING_PLATFORMS
        # blogspot.<country> mirrors of Blogger (dropped from the bundled PSL)
        or icann_reg.split(".", 1)[0] == "blogspot"
        or any(host == h or host.endswith("." + h) for h in HOSTING_HOSTS)
    )

_ranks = None


def _load_ranks() -> dict:
    """registered domain -> Tranco rank, limited to the top 1M. Cached as
    outputs/tranco_rank.joblib so the 1M-row CSV isn't needed at runtime."""
    global _ranks
    if _ranks is None:
        if os.path.exists(_CACHE):
            _ranks = joblib.load(_CACHE)
        elif os.path.exists(_TRANCO_CSV):
            with open(_TRANCO_CSV, encoding="utf-8") as fh:
                _ranks = {row[1].lower(): int(row[0]) for row in csv.reader(fh)}
            joblib.dump(_ranks, _CACHE, compress=3)
        else:
            _ranks = {}
    return _ranks


def _host(url: str) -> str:
    raw = (url or "").strip()
    if not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw
    return (urlparse(raw).hostname or "").lower()


def domain_reputation(url: str, max_rank: int = MAX_RANK) -> dict:
    """
    {"reputable": bool, "domain": registered domain, "rank": int|None,
     "reason": short explanation}
    """
    host = _host(url)
    private_reg = _extract_private(host).top_domain_under_public_suffix if host else ""
    icann_reg = _extract_icann(host).top_domain_under_public_suffix if host else ""
    out = {"reputable": False, "domain": icann_reg or host, "rank": None, "reason": ""}
    if not icann_reg:
        out["reason"] = "no registered domain (IP address or local host)"
        return out
    if is_user_content_host(url):
        out["reason"] = f"hosted on a shared platform ({icann_reg}) where anyone can publish"
        return out
    rank = _load_ranks().get(icann_reg)
    out["rank"] = rank
    if rank is not None and rank <= max_rank:
        out["reputable"] = True
        out["reason"] = f"{icann_reg} is a well-established website (Tranco rank #{rank:,})"
    else:
        out["reason"] = f"{icann_reg} is not among the top {max_rank:,} websites"
    return out
