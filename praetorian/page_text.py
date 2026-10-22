"""Texts for the public page: the method and the feedback box (BG / EN)."""

METHOD = {
    "bg": """
<h2>Как работи — методиката</h2>
<p>Когато излезе нов голям пробив, за часове казваме на собствениците на сайтове дали ги засяга и какво да направят. Безплатно и на прост език.</p>
<div class="steps">
<div class="st"><b>1 · Разбери</b>Четем само първични източници: съобщението на производителя (напр. php.net), каталога на CISA за активно използвани слабости, NVD/CVE, бюлетините на хостинг панелите и дистрибуциите. Медиите са само сигнал. Записваме всичко в „карта на пробива“: какво е, кой софтуер и версии, коя версия го поправя, как личи отвън, какво да направиш. Без източник няма карта.</div>
<div class="st"><b>2 · Провери</b>Гледаме сайта само отвън, както всеки посетител или търсачка: заглавките на отговора, „generator“ в страницата, публичните пътища (напр. на WordPress), версиите в адресите на скриптовете, сертификата и защитните заглавки. Най-много 3 обикновени заявки с паузи.</div>
<div class="st"><b>3 · Предложи</b>Три нива: <i>сам</i> (какво можеш да направиш в панела си), <i>с хостинга</i> (готово писмо за копиране) и <i>с нас</i> (ние поправяме и наблюдаваме). Казваме и кое <b>не</b> трябва да се прави: има „решения“, които запушват една дупка и отварят две.</div>
<div class="st"><b>4 · Докажи</b>След поправката проверката се пуска отново. Версията за сървъра прави сравнение „преди → след“.</div>
</div>
<h3>Какво означават резултатите</h3>
<ul>
<li><b>ЗАСЕГНАТ</b> — версията се вижда и е уязвима.</li>
<li><b>вероятно засегнат</b> — софтуерът се вижда (напр. WordPress върху PHP), но версията е скрита. Точният отговор дава хостингът или версията за сървъра.</li>
<li><b>зависи от хостинга</b> — за този клон няма официална поправка; решава пакетът на доставчика.</li>
<li><b>поправен</b> / <b>не е засегнат</b> — по видимата версия.</li>
<li><b>не личи отвън</b> — сайтът не издава нищо. Това е добре, но не е доказателство.</li>
</ul>
<h3>Какво никога не правим</h3>
<ul>
<li>не опитваме вход, не пращаме атакуващи заявки, не сканираме портове, не натоварваме сайта;</li>
<li>не проверяваме адреси във вътрешни мрежи;</li>
<li>не пазим списъци „кой е засегнат“ и не публикуваме чужди слабости. Отчетът е само за този, който пита.</li>
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
<div class="st"><b>2 · Check</b>We look only from outside, like any visitor or search engine: response headers, the page "generator", public paths (e.g. WordPress), versions in script URLs, the certificate and security headers. At most 3 ordinary requests, with pauses.</div>
<div class="st"><b>3 · Suggest</b>Three levels: <i>yourself</i> (what to do in your panel), <i>with your host</i> (a ready letter to copy) and <i>with us</i> (we fix and monitor). We also say what <b>not</b> to do: some "fixes" close one hole and open two.</div>
<div class="st"><b>4 · Prove</b>After the fix, run the check again. The server edition compares "before → after".</div>
</div>
<h3>What the results mean</h3>
<ul>
<li><b>AFFECTED</b> — the version is visible and vulnerable.</li>
<li><b>likely affected</b> — the software is visible (e.g. WordPress on PHP) but the version is hidden. The exact answer comes from your host or the server edition.</li>
<li><b>depends on your host</b> — no official fix for this branch; the vendor package decides.</li>
<li><b>patched</b> / <b>not affected</b> — by the visible version.</li>
<li><b>not visible from outside</b> — the site reveals nothing. Good, but not proof.</li>
</ul>
<h3>What we never do</h3>
<ul>
<li>no login attempts, no attack payloads, no port scans, no load;</li>
<li>no checks of internal network addresses;</li>
<li>no lists of "who is affected", nobody's weaknesses published. The report is only for the person asking.</li>
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
        "privacy": "Пазим само текста, а име и имейл само ако ги напишете. Не ги даваме на никого и не пращаме реклами. "
                   "За изтриване: office@kagami.bg.",
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
        "privacy": "We keep only the text, plus name and email if you write them. We share them with nobody and send no ads. "
                   "To delete: office@kagami.bg.",
        "thanks": "Thank you! Your message was received.",
        "empty": "Please write a message.",
        "need_consent": "To answer by email, please tick the consent box.",
        "too_many": "Too many messages from you in the last hour. Please try later.",
        "error": "The message could not be saved. Write to office@kagami.bg.",
    },
}
