"""Texts for the public page: the method and the feedback box (BG / EN)."""

METHOD = {
    "bg": """
<h2>Как работи — методиката</h2>
<p>Когато излезе нов голям пробив, за часове казваме на собствениците на сайтове дали ги засяга и какво да направят. Безплатно и на прост език.</p>
<div class="steps">
<div class="st"><b>1 · Разбери</b>Четем само първични източници: съобщението на производителя (напр. php.net), каталога на CISA за активно използвани слабости, NVD/CVE, бюлетините на хостинг панелите и дистрибуциите. Медиите са само сигнал. Записваме всичко в „карта на пробива“: какво е, кой софтуер и версии, коя версия го поправя, как личи отвън, какво да направиш. Без източник няма карта.</div>
<div class="st"><b>2 · Провери</b>Гледаме сайта само отвън, както всеки посетител или търсачка: заглавките на отговора, „generator“ в страницата, версиите в адресите на скриптовете, сертификата и защитните заглавки. Винаги започваме от началната страница. Обикновено 1–3 обикновени заявки, никога повече от 6 (страницата, пренасочванията на самия сайт и — само при WordPress — публичният му фийд), с паузи.</div>
<div class="st"><b>3 · Предложи</b>Три нива: <i>сам</i> (какво можеш да направиш в панела си), <i>с хостинга</i> (готово писмо за копиране) и <i>с нас</i> (ние поправяме и наблюдаваме). Казваме и кое <b>не</b> трябва да се прави: има „решения“, които запушват една дупка и отварят две.</div>
<div class="st"><b>4 · Докажи</b>След поправката проверката се пуска отново. Версията за сървъра прави сравнение „преди → след“.</div>
</div>
<h3>Какво означават резултатите</h3>
<ul>
<li><b>уязвима версия</b> — видимият номер е от засегнатите. Някои хостинги (напр. с CloudLinux) слагат кръпката, без да сменят номера; тогава сайтът е защитен. Потвърждава го хостингът.</li>
<li><b>вероятно засегнат</b> — софтуерът се вижда (напр. WordPress върху PHP), но версията е скрита. Точният отговор дава хостингът или версията за сървъра.</li>
<li><b>зависи от хостинга</b> — за този клон няма официална поправка; решава пакетът на доставчика.</li>
<li><b>поправен</b> / <b>не е засегнат</b> — по видимата версия.</li>
<li><b>не личи отвън</b> — сайтът не издава нищо. Това е добре, но не е доказателство.</li>
</ul>
<h3>Какво никога не правим</h3>
<ul>
<li>не опитваме вход, не пращаме атакуващи заявки, не сканираме портове, не натоварваме сайта;</li>
<li>не проверяваме адреси във вътрешни мрежи;</li>
<li>не публикуваме чужди слабости и не даваме резултатите на никого. Отчетът е само за този, който пита. За статистика записваме кои сайтове са проверени и общия резултат — без IP и без кой е питал.</li>
</ul>
<h3>Две версии, един двигател</h3>
<ul>
<li><b>Онлайн</b> (тази страница): пасивна проверка по адрес.</li>
<li><b>За вашия сървър</b>, с отворен код (Apache-2.0): <a href="https://github.com/galinpd-lgtm/shinkansen-praetorian">github.com/galinpd-lgtm/shinkansen-praetorian</a>. Пуска се на машината и описва всичко инсталирано: ОС, PHP, уеб сървър, бази, WordPress и др., Docker, библиотеки. Сравнява го с картите на пробива, каталога на CISA, OSV и датите за край на поддръжката. Само чете и данните остават при вас.</li>
<li><b>Скоро:</b> версия за цялата локална мрежа на организацията.</li>
</ul>
<p class="m">Източници: php.net · CISA KEV · NVD · OSV.dev · endoflife.date · бюлетините на доставчиците. Текуща карта: PHP2Shell (CVE-2026-109618, CVE-2026-109619).</p>
""",
    "en": """
<h2>How it works — the method</h2>
<p>When a big new vulnerability comes out, within hours we tell website owners whether it affects them and what to do. Free and in plain words.</p>
<div class="steps">
<div class="st"><b>1 · Understand</b>Only primary sources: the vendor notice (e.g. php.net), the CISA catalog of exploited vulnerabilities, NVD/CVE, hosting panel and distribution bulletins. Media are only a signal. Everything goes into a "breach card": what it is, which software and versions, which version fixes it, how it shows from outside, what to do. No source, no card.</div>
<div class="st"><b>2 · Check</b>We look only from outside, like any visitor or search engine: response headers, the page "generator", versions in script URLs, the certificate and security headers. We always start at the home page. Usually 1–3 ordinary requests, never more than 6 (the page, the site's own redirects and, only for WordPress, its public feed), with pauses.</div>
<div class="st"><b>3 · Suggest</b>Three levels: <i>yourself</i> (what to do in your panel), <i>with your host</i> (a ready letter to copy) and <i>with us</i> (we fix and monitor). We also say what <b>not</b> to do: some "fixes" close one hole and open two.</div>
<div class="st"><b>4 · Prove</b>After the fix, run the check again. The server edition compares "before → after".</div>
</div>
<h3>What the results mean</h3>
<ul>
<li><b>vulnerable version</b> — the visible number is an affected one. Some hosts (e.g. with CloudLinux) apply the patch without changing the number; then the site is protected. Your host confirms it.</li>
<li><b>likely affected</b> — the software is visible (e.g. WordPress on PHP) but the version is hidden. The exact answer comes from your host or the server edition.</li>
<li><b>depends on your host</b> — no official fix for this branch; the vendor package decides.</li>
<li><b>patched</b> / <b>not affected</b> — by the visible version.</li>
<li><b>not visible from outside</b> — the site reveals nothing. Good, but not proof.</li>
</ul>
<h3>What we never do</h3>
<ul>
<li>no login attempts, no attack payloads, no port scans, no load;</li>
<li>no checks of internal network addresses;</li>
<li>nobody's weaknesses are published and results are shared with nobody. The report is only for the person asking. For statistics we record which sites were checked and the overall result — no IP, not who asked.</li>
</ul>
<h3>Two editions, one engine</h3>
<ul>
<li><b>Online</b> (this page): passive check by address.</li>
<li><b>For your server</b>, open source (Apache-2.0): <a href="https://github.com/galinpd-lgtm/shinkansen-praetorian">github.com/galinpd-lgtm/shinkansen-praetorian</a>. Runs on the machine and lists everything installed: OS, PHP, web server, databases, WordPress etc., Docker, libraries. Compares it with the breach cards, the CISA catalog, OSV and end-of-life dates. Read-only; your data stays with you.</li>
<li><b>Coming:</b> an edition for an organisation's whole local network.</li>
</ul>
<p class="m">Sources: php.net · CISA KEV · NVD · OSV.dev · endoflife.date · vendor bulletins. Current card: PHP2Shell (CVE-2026-109618, CVE-2026-109619).</p>
""",
}

FEEDBACK = {
    "bg": {
        "title": "Съвети, въпроси и коментари",
        "intro": "Кажете ни какво да добавим, какво не е ясно или какво сте забелязали. Четем всичко.",
        "message": "Вашето съобщение",
        "name": "Име (по желание)",
        "email": "Имейл (по желание, само ако искате отговор)",
        "consent": "Съгласен/съгласна съм имейлът ми да се ползва само за отговор на това съобщение.",
        "send": "Изпрати",
        "privacy": "Пазим текста, а име и имейл само ако ги напишете. Името и имейлът се заличават автоматично след 3 месеца. "
                   "Не ги даваме на никого и не пращаме реклами. За по-ранно изтриване: office@kagami.bg.",
        "thanks": "Благодарим! Съобщението е получено.",
        "empty": "Моля, напишете съобщение.",
        "need_consent": "За да ви отговорим на имейла, отбележете съгласието.",
        "too_many": "Твърде много съобщения от вас за последния час. Опитайте по-късно.",
        "error": "Съобщението не можа да бъде записано. Пишете ни на office@kagami.bg.",
    },
    "en": {
        "title": "Advice, questions and comments",
        "intro": "Tell us what to add, what is unclear or what you noticed. We read everything.",
        "message": "Your message",
        "name": "Name (optional)",
        "email": "Email (optional, only if you want an answer)",
        "consent": "I agree that my email is used only to answer this message.",
        "send": "Send",
        "privacy": "We keep the text, plus name and email if you write them. Name and email are erased automatically after 3 months. "
                   "We share them with nobody and send no ads. To delete earlier: office@kagami.bg.",
        "thanks": "Thank you! Your message was received.",
        "empty": "Please write a message.",
        "need_consent": "To answer by email, please tick the consent box.",
        "too_many": "Too many messages from you in the last hour. Please try later.",
        "error": "The message could not be saved. Write to office@kagami.bg.",
    },
}


# 16.11.2026 — уведомление по чл. 13 GDPR за целия инструмент (след становището на адв. Ангелова от 15.11.2026).
# Всяка промяна тук = нова версия (poshta.SAGLASIE_VERSIA и „versia“ по-долу).
POVERITELNOST = {
    "bg": {
        "vrazka": "Поверителност — всичко за данните",
        "zaglavie": "Поверителност · Praetorian",
        "versia": "Версия от 16.11.2026.",
        "razdeli": [
            ("Кой е администратор", [
                "КАГАМИ ЕООД, ЕИК 103141758, Варна. Контакт по всички въпроси за данните: office@kagami.bg.",
            ]),
            ("Проверката на екрана", [
                "Въвеждате адрес на сайт и виждате резултата на екрана. Не искаме име, имейл или регистрация.",
                "IP адресът Ви се ползва само в паметта на сървъра, за да ограничим броя проверки на час, и не се записва от нас.",
                "За вътрешна статистика записваме проверения сайт, часа, общия резултат и разпознатия софтуер — без IP адрес и без данни кой е питал. "
                "Основание: законният ни интерес да следим натоварването и качеството на проверките (чл. 6, § 1, б. „е“ GDPR). "
                "Адресът на сайта се заличава до 30 дни от проверката; после остават само обобщени показатели без адреса.",
            ]),
            ("Отчетът по имейл (по избор)", [
                "Ако поискате отчета на имейл, обработваме имейл адреса и адреса на сайта, за да потвърдим заявката и да Ви изпратим еднократен отчет. "
                "Основание: Вашето съгласие (чл. 6, § 1, б. „а“ GDPR), дадено с отметка и потвърдено с връзка в писмо. Без потвърждение отчет не се изпраща.",
                "Заличаваме имейл адреса до 7 дни от изпращането на отчета, а при непотвърдена заявка — до 2 дни от подаването ѝ. "
                "Адресът на сайта в заявката се заличава до 30 дни.",
                "Какво остава след това: часът и състоянието на заявката, езикът и запис кога и за коя версия на този текст е дадено съгласието — "
                "без имейл и без нищо, по което да се свърже с Вас. Пазим го, за да можем да покажем, че отчетите се изпращат само след съгласие.",
                "Можете да оттеглите съгласието си по всяко време на office@kagami.bg. Оттеглянето действа занапред.",
            ]),
            ("Съвети, въпроси и коментари", [
                "Пазим текста на съобщението. Име и имейл — само ако ги напишете; имейлът е за отговор и само със съгласие. "
                "Името и имейлът се заличават автоматично след 3 месеца.",
                "Текстът остава след това само ако не позволява да се разпознае авторът или друг човек. Преглеждаме го и при нужда махаме имена, "
                "контакти и разпознаваеми подробности. Съобщенията не се публикуват.",
            ]),
            ("Броячът", [
                "Броим посещенията и натисканията на „Сподели“ на сървъра, по половин час, заедно с домейна на страницата, от която идвате. "
                "Без бисквитки, без IP адрес, без нищо в устройството Ви.",
            ]),
            ("Кой получава данните", [
                "Хостингът на сайта и пощенският сървър, през който се изпращат писмата: SuperHosting.BG (България, ЕС).",
                "Отчетите по имейл се изготвят на собствен сървър на КАГАМИ ЕООД във Варна; той получава само адреса на сайта.",
                "Не предаваме данни извън Европейското икономическо пространство, не ги продаваме и не ги ползваме за реклама.",
                "Хостингът води собствени технически дневници на заявките към сървъра по своите правила.",
            ]),
            ("Вашите права", [
                "Имате право да поискате достъп, коригиране, изтриване, ограничаване и преносимост на данните си, както и да възразите срещу "
                "обработването на основание законен интерес — при приложимите условия. Пишете на office@kagami.bg.",
                "Имате право на жалба до Комисията за защита на личните данни (www.cpdp.bg).",
            ]),
        ],
    },
    "en": {
        "vrazka": "Privacy — all about the data",
        "zaglavie": "Privacy · Praetorian",
        "versia": "Version of 16 November 2026.",
        "razdeli": [
            ("Who is the controller", [
                "KAGAMI Ltd (EIK 103141758), Varna, Bulgaria. Contact for any question about data: office@kagami.bg.",
            ]),
            ("The check on the screen", [
                "You enter a website address and see the result on the screen. We ask for no name, email or registration.",
                "Your IP address is used only in the server's memory to limit checks per hour and is not stored by us.",
                "For internal statistics we record the checked site, the time, the overall result and the detected software — no IP address and nothing about who asked. "
                "Legal basis: our legitimate interest in monitoring load and quality (Art. 6(1)(f) GDPR). "
                "The site address is erased within 30 days of the check; only aggregate figures without the address remain.",
            ]),
            ("The email report (optional)", [
                "If you ask for the report by email, we process the email address and the site address to confirm the request and send you a one-time report. "
                "Legal basis: your consent (Art. 6(1)(a) GDPR), given with a tick box and confirmed through a link by email. Without confirmation no report is sent.",
                "We erase the email address within 7 days after the report is sent, or within 2 days if the request is not confirmed. "
                "The site address in the request is erased within 30 days.",
                "What remains: the time and state of the request, the language and a record of when and for which version of this text consent was given — "
                "with no email and nothing that links it to you. We keep it to show that reports are sent only after consent.",
                "You can withdraw your consent at any time at office@kagami.bg; withdrawal has effect for the future.",
            ]),
            ("Advice, questions and comments", [
                "We keep the text of the message. Name and email only if you write them; the email is for an answer and only with consent. "
                "Name and email are erased automatically after 3 months.",
                "The text stays afterwards only if it does not allow the author or another person to be identified. We review it and remove names, "
                "contacts and identifying details where needed. Messages are not published.",
            ]),
            ("The counter", [
                "We count visits and clicks on “Share” on the server, per half hour, together with the domain of the page you came from. "
                "No cookies, no IP address, nothing on your device.",
            ]),
            ("Who receives the data", [
                "The website host and the mail server that sends the emails: SuperHosting.BG (Bulgaria, EU).",
                "Email reports are produced on KAGAMI Ltd's own server in Varna; it receives only the site address.",
                "We transfer no data outside the European Economic Area, do not sell it and do not use it for advertising.",
                "The host keeps its own technical logs of requests to the server under its own rules.",
            ]),
            ("Your rights", [
                "You have the right to request access, rectification, erasure, restriction and portability, and to object to processing based on "
                "legitimate interest — where applicable. Write to office@kagami.bg.",
                "You have the right to lodge a complaint with the Bulgarian Commission for Personal Data Protection (www.cpdp.bg).",
            ]),
        ],
    },
}
