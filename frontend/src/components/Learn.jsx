import { useState } from 'react'

// Phishing Awareness: what phishing is, why it matters, how PhishGuard AI
// detects it, the terms shown in analysis results, the model's URL
// features (by category) and a quiz per topic. Static content only; best
// quiz scores are kept per browser in localStorage (convenience only).

const TABS = [
  { id: 'basics', label: 'What Is Phishing?' },
  { id: 'detect', label: 'How PhishGuard Detects It' },
  { id: 'features', label: 'URL Features' },
  { id: 'glossary', label: 'Glossary' },
  { id: 'quiz', label: 'Quiz' },
]

// ---------------------------------------------------------------- content

const PHISHING_TYPES = [
  ['Email phishing', 'Mass emails pretending to be a bank, courier or online service, with a link to a fake login page.'],
  ['Spear phishing', 'A message written for one person or company, using real names, job titles or recent events to look genuine.'],
  ['Smishing (SMS)', 'Text messages such as "your parcel is on hold, pay RM1.50 here" with a short link.'],
  ['Vishing (voice)', 'Phone calls from fake bank officers, police or tech support asking for codes or remote access.'],
  ['Clone / look-alike sites', 'A copy of a real website on a domain that looks similar, e.g. paypa1.com or maybank2u-secure.com.'],
  ['Social media & QR codes', 'Fake giveaways, fake customer-support accounts, and QR codes that open phishing pages.'],
]

const WHY_IT_MATTERS = [
  ['Most common entry point', 'Phishing is one of the most frequently reported cybercrimes worldwide and a common first step in data breaches and ransomware attacks.'],
  ['Direct financial loss', 'Stolen banking details and one-time passwords (TAC/OTP) let attackers empty accounts within minutes.'],
  ['Account takeover', 'One stolen password can open email, social media and every other account that reuses it.'],
  ['Hard to spot', 'Phishing pages copy logos and layouts exactly, use HTTPS, and are often online for only hours or days, so blacklists alone are too slow.'],
]

const RED_FLAGS = [
  'Urgency or threats: "your account will be suspended in 24 hours".',
  'The domain is not the brand\'s own (paypal.com.secure-login.xyz, maybank-update.net).',
  'Misspellings or swapped characters in the domain (rn for m, 0 for o, 1 for l).',
  'A link that asks you to log in, "verify" or "update" payment details.',
  'Prizes or refunds you did not expect.',
  'Requests for a TAC/OTP, PIN or password - real organisations never ask for these.',
]

const PIPELINE = [
  ['1. URL clean-up', 'Tracking parameters (utm_*, fbclid, gclid…) and fragments are removed so the same page is always judged the same way. An address typed without http:// or https:// is checked as https://, as the browser would open it.'],
  ['2. Trusted-domain allowlist', 'Well-known official domains are shown as Trusted Website straight away. User-content hosts (e.g. sites.google.com) are not trusted, since anyone can publish there. A redirect link on a trusted service (a Google search result, Outlook Safe Links) is checked by the address it opens.'],
  ['3. Blacklist check (extension)', 'Domains confirmed by the administrator, and websites you blocked yourself, are blocked before the page loads.'],
  ['4. Feature extraction', '22 numeric features are calculated from the URL text only - length, domain, characters, obfuscation, HTTPS and suspicious words. The page itself is never downloaded.'],
  ['5. Random Forest model', 'A Random Forest (many decision trees voting together), trained on the PhiUSIIL dataset plus dated phishing-feed URLs, outputs a phishing probability between 0 and 1.'],
  ['6. Decision thresholds', 'Probability ≥ 0.89 → Phishing (High risk). 0.73 – 0.89 → Suspicious (Medium risk). Below 0.73 → Legitimate (Low risk).'],
  ['7. Domain age check', 'A second machine-learning model (logistic regression) combines the Random Forest score with how long the website\'s domain has existed (looked up in the public domain registry). Phishing domains are usually days or weeks old, so a new domain raises the phishing probability and a domain held for years lowers it. It is skipped for shared hosting platforms and short links, or when the age cannot be found within 3 seconds.'],
  ['8. Safety rules after the model', 'Domain reputation: domains in the Tranco top 250,000 cannot be called Phishing (at most Suspicious). HTTP rule: a reputable site warned only for missing HTTPS is cleared. Reputable-site rule: a long or deep https:// link (document, search or article) on a reputable domain is cleared when the model does not flag the homepage and the address has no lure - login or payment wording, another company\'s brand name, a link to another website or a user@ prefix. Short-link rule: bit.ly, forms.gle and similar links hide their destination, so they are always Suspicious. Brand rule: a well-known brand name, or a one-letter misspelling of it, on a domain the brand does not own raises the verdict one step; a brand spelled with look-alike characters (g00gle, paypa1) is shown as Phishing.'],
  ['9. Live page check', 'For a Suspicious result the server opens the page itself (without running its scripts). A short link is followed and the page it opens is checked instead. A password form that sends to another website, a password asked for in another company\'s name, or a form service collecting passwords makes the result Phishing; a normal page of a well-established website that names only itself makes it Legitimate.'],
  ['10. Explanation & attack type', 'The strongest signals are turned into plain-language reasons, and the attack is classified (Credential Theft, Financial Scam, etc.) with advice on what to do.'],
]

const FEATURE_GROUPS = [
  {
    name: 'Length & size',
    why: 'Phishing URLs are often long, to hide the real domain behind many words, folders and parameters.',
    items: [
      ['URLLength', 'Total number of characters in the URL.'],
      ['DomainLength', 'Number of characters in the hostname.'],
      ['TLDLength', 'Length of the top-level domain (com = 3, info = 4).'],
    ],
  },
  {
    name: 'Domain & TLD',
    why: 'Attackers use raw IP addresses, cheap top-level domains and many subdomains to imitate a brand.',
    items: [
      ['IsDomainIP', '1 if the host is an IP address (http://185.23.4.10/login) instead of a domain name.'],
      ['NoOfSubDomain', 'Number of subdomain levels, e.g. secure.login.paypal.example.com has several.'],
      ['TLDLegitimateProb', 'How often this TLD appears among legitimate sites in the dataset (.com high, rare TLDs low).'],
      ['URLCharProb', 'How "normal" the URL\'s characters are compared with legitimate URLs; random-looking strings score low.'],
    ],
  },
  {
    name: 'Character composition',
    why: 'Legitimate URLs are mostly readable words; phishing kits generate digits, symbols and long query strings.',
    items: [
      ['NoOfLettersInURL / LetterRatioInURL', 'Count and share of letters.'],
      ['NoOfDegitsInURL / DegitRatioInURL', 'Count and share of digits (random IDs, look-alike 0 and 1).'],
      ['NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL', 'Query-string symbols: = ? &.'],
      ['NoOfOtherSpecialCharsInURL / SpacialCharRatioInURL', 'Other symbols such as - _ @ ~ and their share of the URL.'],
    ],
  },
  {
    name: 'Obfuscation',
    why: 'Percent-encoding (%2F, %40) hides the real text of a URL from a quick human glance and simple filters.',
    items: [
      ['HasObfuscation', '1 if the URL contains encoded characters.'],
      ['NoOfObfuscatedChar / ObfuscationRatio', 'How many characters are encoded, and what share of the URL they are.'],
    ],
  },
  {
    name: 'Security',
    why: 'Missing HTTPS is a warning sign, but HTTPS alone does not prove a site is safe - most phishing sites now have a certificate.',
    items: [
      ['IsHTTPS', '1 if the URL uses https://.'],
    ],
  },
  {
    name: 'Words (added by PhishGuard)',
    why: 'The structural features cannot "read" a URL; these two let the model notice login/payment words and brand names in the wrong place.',
    items: [
      ['NoOfSuspiciousWords', 'Number of credential or payment words (login, verify, account, billing…).'],
      ['HasBrandOutsideDomain', '1 if a well-known brand name appears in the URL but the domain is not the brand\'s own.'],
    ],
  },
]

const GLOSSARY = [
  {
    group: 'Verdicts & scores',
    terms: [
      ['Legitimate', 'No significant phishing signs were found. Still check the address before entering a password.'],
      ['Suspicious', 'Some phishing signs were found, but not enough to confirm it. Proceed with caution.'],
      ['Phishing', 'Strong phishing signs. The extension shows a warning page before the site loads.'],
      ['Phishing probability', 'The model\'s estimated chance (0-100%) that the URL is phishing.'],
      ['Confidence', 'How sure the model is about the verdict it gave (the probability of the predicted class).'],
      ['URL Pattern Score', 'The raw model score, shown when a safety rule (reputation, HTTP, reputable-site, short-link or brand rule) changed the final verdict.'],
      ['Risk level', 'Low / Medium / High - a simple summary of the verdict for users.'],
      ['Threshold', 'The cut-off probability that separates verdicts (0.73 for Suspicious, 0.89 for Phishing).'],
      ['False positive / false negative', 'A safe site wrongly flagged / a phishing site wrongly allowed.'],
    ],
  },
  {
    group: 'Parts of a URL',
    terms: [
      ['Domain (hostname)', 'The site\'s name, e.g. www.maybank2u.com.my.'],
      ['Registered domain', 'The part an owner actually registers (maybank2u.com.my). Everything to its left is a subdomain anyone with that domain can create.'],
      ['Subdomain', 'Labels in front of the registered domain, e.g. "login" in login.example.com. paypal.com.evil.net belongs to evil.net, not PayPal.'],
      ['TLD (top-level domain)', 'The last label: .com, .my, .xyz.'],
      ['Path & query string', 'Everything after the domain: /account/verify?id=123.'],
      ['IP-based URL', 'A link that uses numbers (http://203.0.113.5/) instead of a domain name.'],
      ['Percent-encoding (obfuscation)', 'Characters written as %XX codes, e.g. %40 for @, to hide text.'],
      ['HTTPS / TLS', 'Encrypts the connection. It protects data in transit but says nothing about who owns the site.'],
      ['URL shortener', 'Services like bit.ly that hide the real destination.'],
    ],
  },
  {
    group: 'Detection techniques',
    terms: [
      ['Machine learning model', 'A program that learns patterns from labelled examples instead of fixed rules.'],
      ['Random Forest', 'An ensemble of many decision trees; each tree votes and the average becomes the phishing probability.'],
      ['Feature', 'A measurable property of a URL (its length, number of digits, uses HTTPS…) given to the model.'],
      ['Feature importance', 'How much each feature contributed to the model\'s decisions (see Model Analytics).'],
      ['Allowlist', 'A list of known official domains that are always treated as legitimate.'],
      ['Blacklist (blocklist)', 'A list of confirmed phishing domains that are always blocked.'],
      ['Domain reputation (Tranco)', 'Tranco is a research ranking of the most popular websites; highly ranked, long-established domains are rarely phishing.'],
      ['PhiUSIIL dataset', 'A public dataset of about 235,000 labelled legitimate and phishing URLs used to train the model.'],
    ],
  },
  {
    group: 'Attack types',
    terms: [
      ['Credential Theft', 'A fake login page that captures usernames and passwords.'],
      ['Financial Scam', 'Imitates banks, payment or billing pages to steal card or banking details.'],
      ['Fake Giveaway / Scam', 'Promises prizes, rewards or free items in exchange for data or a "fee".'],
      ['Tech Support / Malware Scam', 'Fake virus alerts or downloads that install malware or push you to call scammers.'],
      ['Domain Spoofing / Brand Impersonation', 'Uses a brand name on a domain the brand does not own.'],
      ['Typosquatting', 'Registering misspelled domains (gooogle.com, faceb00k.com).'],
      ['Homograph attack', 'Using look-alike characters from other alphabets (Cyrillic "а" instead of Latin "a").'],
    ],
  },
]

// Each question: q, options, answer (index), why. Question order and option
// order are shuffled on every attempt; `fixed` (or `fixedOptions` on a quiz)
// keeps options whose order carries meaning (Legitimate < Suspicious < Phishing).
const QUIZZES = [
  {
    id: 'basics',
    name: 'Phishing Basics',
    questions: [
      { q: 'What is the main goal of a phishing attack?', options: ['To speed up your internet', 'To trick you into giving away information or money', 'To advertise a product', 'To test your antivirus'], answer: 1, why: 'Phishing uses deception to steal credentials, payment details or personal data.' },
      { q: 'A phishing attack sent by SMS is called…', options: ['Vishing', 'Pharming', 'Smishing', 'Spoofing'], answer: 2, why: 'SMS + phishing = smishing. Vishing is by voice call.' },
      { q: 'Spear phishing is different because it…', options: ['Only uses phone calls', 'Targets a specific person or organisation with personalised details', 'Only targets banks', 'Uses no links'], answer: 1, why: 'Spear phishing is tailored to one target, making it more convincing.' },
      { q: 'Your "bank" emails: "Account locked! Verify within 1 hour". What is the biggest red flag?', options: ['It mentions your bank', 'The urgent threat pushing you to act fast', 'It was sent in the morning', 'It has a logo'], answer: 1, why: 'Urgency stops you from thinking carefully - a classic social-engineering trick.' },
      { q: 'A real bank will ask for your TAC/OTP by phone or email…', options: ['Sometimes', 'Only for large transfers', 'Never', 'Only on weekends'], answer: 2, why: 'Legitimate organisations never ask you to share a one-time password.' },
      { q: 'Why can\'t blacklists alone stop phishing?', options: ['They are too large', 'New phishing sites appear and disappear within hours, before they are listed', 'Browsers ignore them', 'They only work on mobile'], answer: 1, why: 'This is why PhishGuard uses a machine learning model that can judge URLs it has never seen.' },
      { q: 'A caller pretending to be a bank officer asks for your TAC. This is called…', options: ['Smishing', 'Vishing', 'Typosquatting', 'Spear phishing'], answer: 1, why: 'Voice + phishing = vishing. The caller wants the code to approve a transaction.' },
      { q: 'A copy of a real website hosted on a similar-looking domain such as paypa1.com is a…', options: ['Clone / look-alike site', 'Browser extension', 'Pop-up advert', 'Software update'], answer: 0, why: 'Clone sites copy the real layout and logo so only the address gives them away.' },
      { q: 'What do phishers most often want from you?', options: ['Your screen resolution', 'Login credentials, banking details or personal data', 'Your favourite colour', 'Your browser history'], answer: 1, why: 'Stolen credentials and payment details can be used or sold straight away.' },
      { q: 'A QR code on a poster opens a "login to claim reward" page. Why is this risky?', options: ['QR codes are always safe', 'You cannot see the real address before it opens, so it may be a phishing page', 'QR codes slow down your phone', 'It only works on Wi-Fi'], answer: 1, why: 'QR codes hide the link the same way short links do. Check the address before typing anything.' },
    ],
  },
  {
    id: 'spot',
    name: 'Spot the Phishing URL',
    fixedOptions: true,
    questions: [
      { q: 'https://www.paypal.com/myaccount/summary', options: ['Legitimate', 'Phishing'], answer: 0, why: 'The registered domain is paypal.com - PayPal\'s own.' },
      { q: 'https://paypal.com.account-verify.info/login', options: ['Legitimate', 'Phishing'], answer: 1, why: 'The registered domain is account-verify.info. "paypal.com" is only a subdomain.' },
      { q: 'http://185.23.4.10/maybank2u/login.php', options: ['Legitimate', 'Phishing'], answer: 1, why: 'A bank login on a raw IP address over plain HTTP is a strong phishing sign.' },
      { q: 'https://www.maybank2u.com.my/home/m2u/common/login.do', options: ['Legitimate', 'Phishing'], answer: 0, why: 'maybank2u.com.my is Maybank\'s official online-banking domain.' },
      { q: 'https://secure-appleid.apple.com-support.xyz/verify', options: ['Legitimate', 'Phishing'], answer: 1, why: 'The real domain is com-support.xyz; "apple" only appears in the subdomain.' },
      { q: 'https://accounts.google.com/signin', options: ['Legitimate', 'Phishing'], answer: 0, why: 'accounts is a subdomain of google.com, Google\'s own domain.' },
      { q: 'https://faceb00k-login.com/', options: ['Legitimate', 'Phishing'], answer: 1, why: 'Typosquatting: zeros instead of the letter "o".' },
      { q: 'https://sites.google.com/view/shopee-reward-claim', options: ['Legitimate', 'Phishing'], answer: 1, why: 'Anyone can publish on sites.google.com, so "google" in the domain proves nothing. A free reward claim page is a giveaway scam.' },
      { q: 'https://shopee.com.my/user/purchase', options: ['Legitimate', 'Phishing'], answer: 0, why: 'shopee.com.my is Shopee Malaysia\'s own domain; /user/purchase is just a page on it.' },
      { q: 'http://www.paypa1.com/signin', options: ['Legitimate', 'Phishing'], answer: 1, why: 'Look-alike character: the digit "1" replaces the letter "l" in PayPal, and it is plain HTTP.' },
    ],
  },
  {
    id: 'features',
    name: 'URL Features (Dataset)',
    questions: [
      { q: 'Which feature is 1 for http://185.23.4.10/login?', options: ['IsHTTPS', 'IsDomainIP', 'HasObfuscation', 'HasBrandOutsideDomain'], answer: 1, why: 'IsDomainIP flags URLs that use an IP address instead of a domain name.' },
      { q: 'What does HasObfuscation detect?', options: ['Very long domains', 'Percent-encoded characters such as %2F or %40', 'Missing HTTPS', 'Uppercase letters'], answer: 1, why: 'Encoded characters hide the real text of the URL.' },
      { q: 'Which feature belongs to the "Domain & TLD" category?', options: ['NoOfAmpersandInURL', 'TLDLegitimateProb', 'ObfuscationRatio', 'NoOfSuspiciousWords'], answer: 1, why: 'TLDLegitimateProb measures how common the TLD is among legitimate sites.' },
      { q: 'https://login.secure.update.bank.example.xyz has a high value for…', options: ['NoOfSubDomain', 'IsDomainIP', 'NoOfQMarkInURL', 'HasObfuscation'], answer: 0, why: 'Many subdomain levels are used to push the real domain out of view.' },
      { q: 'Why is IsHTTPS = 1 NOT proof that a site is safe?', options: ['HTTPS is outdated', 'Phishing sites can get free certificates too', 'HTTPS only works on Chrome', 'It is - HTTPS sites are always safe'], answer: 1, why: 'HTTPS encrypts the connection but does not verify who owns the site.' },
      { q: 'Which feature did PhishGuard add on top of the dataset\'s structural features?', options: ['URLLength', 'IsHTTPS', 'HasBrandOutsideDomain', 'DomainLength'], answer: 2, why: 'HasBrandOutsideDomain and NoOfSuspiciousWords let the model "read" words in the URL.' },
      { q: 'A very high DegitRatioInURL usually means…', options: ['A readable, word-based URL', 'Many digits, e.g. random IDs or look-alike characters', 'The site uses HTTPS', 'The domain is short'], answer: 1, why: 'Legitimate URLs are mostly letters; phishing kits often generate digit-heavy strings.' },
      { q: 'NoOfSuspiciousWords counts words such as…', options: ['login, verify, account, billing', 'home, about, contact', 'www, com, net', 'jpg, png, gif'], answer: 0, why: 'Credential and payment words are common in phishing URLs that imitate login or billing pages.' },
      { q: 'Which feature counts the "?" symbols in a URL?', options: ['NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'TLDLength'], answer: 1, why: 'NoOfQMarkInURL is one of the query-string symbol counts (= ? &).' },
      { q: 'For http://example.com/login, what is the value of IsHTTPS?', options: ['0', '1', '22', 'It is not calculated'], answer: 0, why: 'The URL starts with http://, not https://, so IsHTTPS = 0.' },
    ],
  },
  {
    id: 'results',
    name: 'Reading PhishGuard Results',
    questions: [
      { q: 'The model gives a phishing probability of 0.80. What is the verdict?', options: ['Legitimate', 'Suspicious', 'Phishing'], answer: 1, fixed: true, why: '0.73 – 0.89 is Suspicious (Medium risk); ≥ 0.89 is Phishing.' },
      { q: 'The model gives a phishing probability of 0.95. What is the verdict?', options: ['Legitimate', 'Suspicious', 'Phishing'], answer: 2, fixed: true, why: '0.89 or above is Phishing (High risk).' },
      { q: 'A domain in the Tranco top 250,000 can be shown as at most…', options: ['Legitimate', 'Suspicious', 'Phishing'], answer: 1, fixed: true, why: 'The domain reputation rule stops popular, long-established sites from being called Phishing.' },
      { q: 'You analyse a bit.ly short link. What does the short-link rule do?', options: ['Always trusts it', 'Shows it as Suspicious because the real destination is hidden', 'Blocks bit.ly for everyone', 'Ignores the link'], answer: 1, why: 'Short links hide where they go, so they are Suspicious; the live page check then follows the link.' },
      { q: 'The domain age check finds the domain was registered 3 days ago. What happens to the phishing probability?', options: ['It goes up', 'It goes down', 'It does not change', 'The scan stops'], answer: 0, why: 'Phishing domains are usually days or weeks old, so a very new domain raises the probability.' },
      { q: 'When does the server run the live page check?', options: ['For every URL', 'When the result is Suspicious', 'Only for trusted websites', 'Only when an admin asks'], answer: 1, why: 'The live page check opens Suspicious pages (without running scripts) and looks for password forms that send data to another website.' },
      { q: 'What does "Risk Level: High" mean?', options: ['The site is slow', 'Strong evidence of phishing - do not continue', 'The site uses many ads', 'The model is unsure'], answer: 1, why: 'High risk corresponds to a Phishing verdict.' },
      { q: 'When is a "URL Pattern Score" shown instead of the phishing probability?', options: ['Always', 'When a safety rule after the model changed the final verdict', 'Only for admins', 'When the site is offline'], answer: 1, why: 'It shows the raw model score honestly, with the rule that overrode it.' },
      { q: 'You blocked a site from the extension. How do you unblock it?', options: ['Press Continue Access on the block page', 'Reinstall Chrome', 'Log in to your PhishGuard account and use Blocked Websites → Unblock', 'Clear browser history'], answer: 2, why: 'Blocks can only be lifted from your account, so a block cannot be bypassed by accident.' },
      { q: 'An admin-confirmed blacklist entry means…', options: ['Only you are blocked', 'The administrator reviewed a report and blocked the domain for all users', 'The site is temporarily offline', 'The model was not used'], answer: 1, why: 'Reports are reviewed by the admin ("Save in Database") before being added to the blacklist.' },
    ],
  },
  {
    id: 'safety',
    name: 'Staying Safe',
    questions: [
      { q: 'You entered your password on a phishing site. What should you do first?', options: ['Wait and see', 'Change the password immediately (and anywhere you reused it)', 'Delete the email', 'Restart your computer'], answer: 1, why: 'Change it at once and enable two-factor authentication.' },
      { q: 'The safest way to visit your bank is…', options: ['Click the link in the SMS', 'Type the official address or use the official app/bookmark', 'Search and click the first ad', 'Use a link from social media'], answer: 1, why: 'Going directly avoids look-alike links entirely.' },
      { q: 'Two-factor authentication (2FA) helps because…', options: ['It makes passwords longer', 'A stolen password alone is not enough to log in', 'It blocks all phishing emails', 'It hides your IP address'], answer: 1, why: 'The attacker also needs your second factor (app code, security key).' },
      { q: 'What should you do with a suspicious link you received?', options: ['Forward it to friends to ask', 'Analyse it with PhishGuard and report it', 'Open it in incognito mode to check', 'Ignore all links forever'], answer: 1, why: 'Reporting helps the admin block it for every user.' },
      { q: 'Using the same password on many sites is risky because…', options: ['It is hard to remember', 'One phishing attack exposes all those accounts', 'Websites do not allow it', 'It slows down login'], answer: 1, why: 'Attackers try stolen passwords on many services ("credential stuffing").' },
      { q: 'Before typing your password on a page, what should you check first?', options: ['The page colour', 'The domain in the address bar', 'The number of images', 'The page loading speed'], answer: 1, why: 'Only the registered domain tells you who owns the site; logos and layouts can be copied.' },
      { q: 'How can you see where a link really goes before clicking it?', options: ['Hover over it (or long-press on mobile) and read the address', 'Click it quickly and close the tab', 'Count the words in the message', 'Check the sender\'s profile picture'], answer: 0, why: 'The visible link text can say anything; the real address is shown when you hover.' },
      { q: 'A pop-up says "Your PC is infected! Call this number now". What should you do?', options: ['Call the number', 'Close the page and do not call or download anything', 'Pay for the cleaning tool', 'Give them remote access'], answer: 1, why: 'This is a tech support scam. Real antivirus software never asks you to call a number from a web page.' },
      { q: 'Your "manager" emails asking you to buy gift cards urgently and keep it secret. What should you do?', options: ['Buy them quickly', 'Verify by contacting your manager through a known phone number or in person', 'Reply with your bank details', 'Forward it to all colleagues'], answer: 1, why: 'Urgency plus secrecy is a classic impersonation trick. Verify using a channel you already trust.' },
      { q: 'A password manager helps protect you from phishing because…', options: ['It will not autofill your password on a look-alike domain', 'It blocks all emails', 'It makes your internet faster', 'It hides your IP address'], answer: 0, why: 'It matches the exact domain, so paypa1.com gets nothing even if it looks like PayPal.' },
    ],
  },
]

// ---------------------------------------------------------------- storage

const BEST_KEY = 'pg_quiz_best'
const loadBest = () => {
  try { return JSON.parse(localStorage.getItem(BEST_KEY)) || {} } catch { return {} }
}
const saveBest = (best) => {
  try { localStorage.setItem(BEST_KEY, JSON.stringify(best)) } catch { /* storage unavailable */ }
}

const shuffle = (arr) => {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

// A fresh attempt: questions in random order, options shuffled with the
// answer index remapped.
const buildDeck = (quiz) => shuffle(quiz.questions).map((item) => {
  if (quiz.fixedOptions || item.fixed) return item
  const order = shuffle(item.options.map((_, i) => i))
  return { ...item, options: order.map((i) => item.options[i]), answer: order.indexOf(item.answer) }
})

// ---------------------------------------------------------------- views

function Basics() {
  return (
    <>
      <section className="panel">
        <h3>What is phishing?</h3>
        <p className="learn-lead">
          <b>Phishing</b> is a social-engineering attack in which a criminal pretends to be a
          trusted organisation - a bank, delivery company, university or online shop - to trick
          you into opening a fake website and giving away passwords, banking details or personal
          information. The fake website is the "hook"; your trust is the "bait".
        </p>
        <div className="learn-grid">
          {PHISHING_TYPES.map(([t, d]) => (
            <div className="learn-card" key={t}><b>{t}</b><p>{d}</p></div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h3>Why is phishing important?</h3>
        <div className="learn-grid">
          {WHY_IT_MATTERS.map(([t, d]) => (
            <div className="learn-card" key={t}><b>{t}</b><p>{d}</p></div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h3>Red flags to look for</h3>
        <ul className="learn-list">
          {RED_FLAGS.map((r) => <li key={r}>{r}</li>)}
        </ul>
        <div className="learn-callout">
          <b>Read the domain from right to left.</b> In <span className="mono">https://paypal.com.secure-login.xyz/verify</span>,
          the real website is <span className="mono">secure-login.xyz</span> - not PayPal.
        </div>
      </section>
    </>
  )
}

function Detect() {
  return (
    <section className="panel">
      <h3>From URL to verdict</h3>
      <p className="learn-lead">
        Every URL you analyse on this website, and every page the Chrome extension intercepts,
        goes through the same steps. Only the URL text is analysed, so a phishing page is judged
        before it can load or run anything.
      </p>
      <ol className="learn-steps">
        {PIPELINE.map(([t, d]) => (
          <li key={t}><b>{t}</b><p>{d}</p></li>
        ))}
      </ol>
      <div className="learn-callout">
        Try it: open <b>Analyse URL</b>, paste a link, and compare the reasons shown with the
        steps above. Unfamiliar terms are explained in the <b>Glossary</b> tab.
      </div>
    </section>
  )
}

function Features() {
  return (
    <>
      <section className="panel">
        <h3>The 22 URL features the model uses</h3>
        <p className="learn-lead">
          20 features come from the PhiUSIIL Phishing URL dataset (URL-only features, so no web
          page has to be downloaded); 2 word-level features were added by PhishGuard. They are
          grouped below by what they measure.
        </p>
      </section>
      {FEATURE_GROUPS.map((g) => (
        <section className="panel" key={g.name}>
          <h3>{g.name}</h3>
          <p className="muted learn-why">{g.why}</p>
          <table className="hist">
            <tbody>
              {g.items.map(([f, d]) => (
                <tr key={f}><td className="mono learn-feature">{f}</td><td>{d}</td></tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </>
  )
}

function Glossary() {
  const [q, setQ] = useState('')
  const needle = q.toLowerCase()
  return (
    <>
      <section className="panel">
        <input
          className="scan-input"
          placeholder="Search a term, e.g. subdomain, threshold, Random Forest…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </section>
      {GLOSSARY.map((g) => {
        const terms = g.terms.filter(([t, d]) => !q || `${t} ${d}`.toLowerCase().includes(needle))
        if (!terms.length) return null
        return (
          <section className="panel" key={g.group}>
            <h3>{g.group}</h3>
            <dl className="learn-dl">
              {terms.map(([t, d]) => (
                <div key={t}><dt>{t}</dt><dd>{d}</dd></div>
              ))}
            </dl>
          </section>
        )
      })}
    </>
  )
}

function Quiz() {
  const [best, setBest] = useState(loadBest)
  const [quizId, setQuizId] = useState(null)
  const [deck, setDeck] = useState([])
  const [index, setIndex] = useState(0)
  const [picked, setPicked] = useState(null)
  const [score, setScore] = useState(0)
  const [done, setDone] = useState(false)

  const quiz = QUIZZES.find((x) => x.id === quizId)

  const start = (id) => {
    setDeck(buildDeck(QUIZZES.find((x) => x.id === id)))
    setQuizId(id); setIndex(0); setPicked(null); setScore(0); setDone(false)
  }

  if (!quiz) {
    return (
      <section className="panel">
        <h3>Choose a quiz category</h3>
        <div className="learn-grid">
          {QUIZZES.map((x) => (
            <button key={x.id} className="learn-card learn-quiz-pick" onClick={() => start(x.id)}>
              <b>{x.name}</b>
              <p>{x.questions.length} questions</p>
              <p className="muted">
                {best[x.id] != null ? `Best score: ${best[x.id]} / ${x.questions.length}` : 'Not attempted yet'}
              </p>
            </button>
          ))}
        </div>
      </section>
    )
  }

  const total = quiz.questions.length

  if (done) {
    const pct = Math.round((score / total) * 100)
    return (
      <section className="panel">
        <h3>{quiz.name} - Result</h3>
        <p className="learn-score">{score} / {total} ({pct}%)</p>
        <p className="muted">
          {pct === 100 ? 'Perfect! You can spot these attacks.'
            : pct >= 70 ? 'Good job - review the explanations for the ones you missed.'
            : 'Keep learning - read the other tabs and try again.'}
        </p>
        <div className="learn-actions">
          <button className="scan-btn" onClick={() => start(quiz.id)}>Try again</button>
          <button className="scan-btn secondary" onClick={() => setQuizId(null)}>Other categories</button>
        </div>
      </section>
    )
  }

  const item = deck[index]
  const answered = picked != null

  const choose = (i) => {
    if (answered) return
    setPicked(i)
    if (i === item.answer) setScore((s) => s + 1)
  }

  const next = () => {
    if (index + 1 < total) {
      setIndex(index + 1); setPicked(null)
      return
    }
    const nextBest = { ...best, [quiz.id]: Math.max(best[quiz.id] ?? 0, score) }
    setBest(nextBest); saveBest(nextBest); setDone(true)
  }

  return (
    <section className="panel">
      <div className="learn-quiz-head">
        <h3>{quiz.name}</h3>
        <span className="muted">Question {index + 1} of {total} · Score {score}</span>
      </div>
      <div className="learn-progress"><div style={{ width: `${(index / total) * 100}%` }} /></div>
      <p className={`learn-question ${quiz.id === 'spot' ? 'mono' : ''}`}>{item.q}</p>
      {quiz.id === 'spot' && <p className="muted">Is this URL legitimate or phishing?</p>}
      <div className="learn-options">
        {item.options.map((o, i) => {
          let cls = 'learn-option'
          if (answered && i === item.answer) cls += ' correct'
          else if (answered && i === picked) cls += ' wrong'
          return <button key={o} className={cls} onClick={() => choose(i)} disabled={answered}>{o}</button>
        })}
      </div>
      {answered && (
        <div className={`learn-callout ${picked === item.answer ? 'good' : 'bad'}`}>
          <b>{picked === item.answer ? 'Correct.' : 'Not quite.'}</b> {item.why}
        </div>
      )}
      <div className="learn-actions">
        <button className="scan-btn secondary" onClick={() => setQuizId(null)}>Quit</button>
        <button className="scan-btn" onClick={next} disabled={!answered}>
          {index + 1 < total ? 'Next question' : 'See result'}
        </button>
      </div>
    </section>
  )
}

export default function Learn() {
  const [tab, setTab] = useState('basics')
  return (
    <>
      <div className="page-header">
        <h2>Phishing Awareness</h2>
        <p className="tagline">
          Learn what phishing is, how PhishGuard AI detects it, what the terms in your results mean,
          and test yourself with a quiz.
        </p>
      </div>
      <div className="seg-tabs">
        {TABS.map((t) => (
          <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === 'basics' && <Basics />}
      {tab === 'detect' && <Detect />}
      {tab === 'features' && <Features />}
      {tab === 'glossary' && <Glossary />}
      {tab === 'quiz' && <Quiz />}
    </>
  )
}
