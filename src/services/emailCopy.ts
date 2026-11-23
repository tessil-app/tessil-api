// The words of every email, per language. Builders in email.service.ts lay
// them out as text and HTML.

export const MAIL_LOCALES = ["en", "nl"] as const;
export type MailLocale = (typeof MAIL_LOCALES)[number];

/** A stored or requested language, or English when there is none. */
export function mailLocale(value: unknown): MailLocale {
  return MAIL_LOCALES.includes(value as MailLocale) ? (value as MailLocale) : "en";
}

type Noun = "portal" | "form";

const en = {
  signoff: "Tessil",
  unknown: "unknown",
  unknownPlace: "an unknown location",
  magic: {
    subject: "Your Tessil sign-in link",
    heading: "Sign in to Tessil",
    intro: (minutes: number) => `Click the link below to sign in. It expires in ${minutes} minutes and can only be used once.`,
    introHtml: (minutes: number) =>
      `Click the button below to sign in. The link expires in <strong>${minutes} minutes</strong> and can only be used once.`,
    button: "Sign in to Tessil",
    paste: "Or paste this URL into your browser:",
    otherDevice:
      "If you open this link on a different device than the one you started signing in on, we show you a short code to type back into your original device. No sign-in happens on the wrong device.",
    details: "Request details",
    location: "Location",
    browser: "Browser",
    noIp: "We show approximate location and network rather than your IP address. Tessil does not store the IP itself.",
    notYou: "If you didn't request this, ignore this email. No account changes were made.",
  },
  deleted: {
    subject: "Your Tessil account was deleted",
    body: "Your Tessil account and all associated transfers were permanently deleted just now.",
    notYou: (email: string) =>
      `If you did this, no further action is needed. If you did not request this deletion, your account may have been accessed by someone else. We recommend changing the password of the email address used to sign in (${email}), and reviewing other services where you used the same address.`,
    noCopies: "We don't retain copies. The account and its files cannot be restored.",
  },
  anomaly: {
    subject: "Heads up: your Tessil session is being used from a new network",
    title: "Tessil session change",
    heading: "A Tessil session is on a new network",
    noticed: "We noticed a change of network on one of your Tessil sessions.",
    moved: (previous: string, current: string) =>
      `Your session previously seen from ${previous} is now being used from ${current}.`,
    session: (date: string) => `Affected session: signed in on ${date}`,
    from: "from",
    ifNot: "If this wasn't you, sign out everywhere from your dashboard settings:",
    button: "Sign out everywhere",
    ifYou:
      "If this was you (you're travelling, on a VPN, or switched networks), you can ignore this email. We won't sign you out automatically.",
    noIp: "We show approximate country and network rather than your IP address. Tessil does not store the IP itself.",
  },
  notice: {
    invited: {
      subject: (owner: string, noun: Noun) => `${owner} wants to share a Tessil ${noun} with you`,
      heading: (noun: Noun) => `You're invited to a ${noun}`,
      what: (owner: string, noun: Noun) =>
        noun === "form"
          ? `${owner} wants to share a form with you on Tessil. A form is a link through which other people answer their questions, encrypted so only its members can read the answers.`
          : `${owner} wants to share a portal with you on Tessil. A portal is a link through which other people send them files, encrypted so only its members can open them.`,
      next: "Sign in with this email address and set up a vault. A free account is enough. They can then give you access, and we'll email you when they have.",
      button: "Sign in to Tessil",
      footnote: (owner: string) => `If you don't know ${owner}, ignore this email. Nothing happens unless you sign in.`,
    },
    ready: {
      subject: (invitee: string, noun: Noun) => `${invitee} is ready for your ${noun}`,
      heading: "Your invite is ready",
      body: (invitee: string, noun: Noun) =>
        `${invitee} has signed in and set up a vault. Open the ${noun} and choose Sharing to give them access.`,
      why: (noun: Noun) => `This step happens in your browser, because only you hold the ${noun}'s keys.`,
      button: (noun: Noun) => `Open the ${noun}`,
      footnote: (noun: Noun) => `You're getting this because you invited them to a ${noun}.`,
    },
    given: {
      subject: (owner: string, noun: Noun) => `${owner} shared a Tessil ${noun} with you`,
      heading: (noun: Noun) => `A ${noun} was shared with you`,
      body: (owner: string, noun: Noun) =>
        `${owner} gave you access to a ${noun}. Open your ${noun}s and accept it to see ${noun === "form" ? "the responses" : "the files sent to it"}.`,
      button: (noun: Noun) => `View your ${noun}s`,
      footnote: (owner: string) => `If you don't know ${owner}, you can decline it there.`,
    },
    response: {
      subject: "A new response to one of your Tessil forms",
      heading: "A new response arrived",
      body: "Someone filled in one of your forms. Open it to read their answers.",
      why: "We can't tell you which form by name or what was answered: both are encrypted and only you can read them.",
      button: "Open the form",
      footnote: "At most one of these per form per hour. The form's owner can switch them off in its settings.",
    },
    files: {
      subject: "New files in one of your Tessil portals",
      heading: "New files arrived",
      body: "Someone sent files through one of your portals. Open it to see what came in.",
      why: "We can't tell you which portal by name or what was sent: both are encrypted and only you can read them.",
      button: "Open the portal",
      footnote: "At most one of these per portal per hour. The portal's owner can switch them off in its settings.",
    },
  },
};

const NL_NOUN: Record<Noun, { word: string; plural: string }> = {
  portal: { word: "portaal", plural: "portalen" },
  form: { word: "formulier", plural: "formulieren" },
};

const nl: typeof en = {
  signoff: "Tessil",
  unknown: "onbekend",
  unknownPlace: "een onbekende plek",
  magic: {
    subject: "Je inloglink voor Tessil",
    heading: "Inloggen bij Tessil",
    intro: (minutes: number) =>
      `Klik op de link hieronder om in te loggen. Hij verloopt over ${minutes} minuten en werkt maar één keer.`,
    introHtml: (minutes: number) =>
      `Klik op de knop hieronder om in te loggen. De link verloopt over <strong>${minutes} minuten</strong> en werkt maar één keer.`,
    button: "Inloggen bij Tessil",
    paste: "Of plak deze URL in je browser:",
    otherDevice:
      "Open je deze link op een ander apparaat dan waar je begon met inloggen, dan tonen we een korte code om op je eerste apparaat in te typen. Op het verkeerde apparaat word je niet ingelogd.",
    details: "Gegevens van het verzoek",
    location: "Locatie",
    browser: "Browser",
    noIp: "We tonen een globale locatie en het netwerk in plaats van je IP-adres. Tessil bewaart het IP-adres zelf niet.",
    notYou: "Heb je dit niet aangevraagd? Negeer deze e-mail dan. Er is niets aan je account veranderd.",
  },
  deleted: {
    subject: "Je Tessil-account is verwijderd",
    body: "Je Tessil-account en alle bijbehorende transfers zijn zojuist voorgoed verwijderd.",
    notYou: (email: string) =>
      `Deed je dit zelf, dan hoef je niets te doen. Heb je niet om verwijdering gevraagd, dan heeft misschien iemand anders toegang gehad tot je account. Verander dan het wachtwoord van het e-mailadres waarmee je inlogde (${email}) en kijk ook naar andere diensten waar je hetzelfde adres gebruikt.`,
    noCopies: "We bewaren geen kopieën. Het account en de bestanden kunnen niet worden teruggezet.",
  },
  anomaly: {
    subject: "Let op: je Tessil-sessie wordt gebruikt vanaf een nieuw netwerk",
    title: "Wijziging in een Tessil-sessie",
    heading: "Een Tessil-sessie zit op een nieuw netwerk",
    noticed: "We zagen dat een van je Tessil-sessies van netwerk is gewisseld.",
    moved: (previous: string, current: string) =>
      `Je sessie die eerder werd gezien vanuit ${previous}, wordt nu gebruikt vanuit ${current}.`,
    session: (date: string) => `Betreffende sessie: ingelogd op ${date}`,
    from: "vanaf",
    ifNot: "Was jij dit niet? Log dan overal uit via de instellingen in je dashboard:",
    button: "Overal uitloggen",
    ifYou:
      "Was jij het wel (op reis, via een VPN of op een ander netwerk), dan kun je deze e-mail negeren. We loggen je niet automatisch uit.",
    noIp: "We tonen een globaal land en het netwerk in plaats van je IP-adres. Tessil bewaart het IP-adres zelf niet.",
  },
  notice: {
    invited: {
      subject: (owner: string, noun: Noun) => `${owner} wil een Tessil-${NL_NOUN[noun].word} met je delen`,
      heading: (noun: Noun) => `Je bent uitgenodigd voor een ${NL_NOUN[noun].word}`,
      what: (owner: string, noun: Noun) =>
        noun === "form"
          ? `${owner} wil een formulier met je delen op Tessil. Een formulier is een link waarmee anderen vragen beantwoorden, versleuteld zodat alleen de leden de antwoorden kunnen lezen.`
          : `${owner} wil een portaal met je delen op Tessil. Een portaal is een link waarmee anderen bestanden sturen, versleuteld zodat alleen de leden ze kunnen openen.`,
      next: "Log in met dit e-mailadres en stel een kluis in. Een gratis account is genoeg. Daarna kan diegene je toegang geven, en we mailen je zodra dat gebeurd is.",
      button: "Inloggen bij Tessil",
      footnote: (owner: string) => `Ken je ${owner} niet? Negeer deze e-mail dan. Er gebeurt niets zolang je niet inlogt.`,
    },
    ready: {
      subject: (invitee: string, noun: Noun) => `${invitee} is klaar voor je ${NL_NOUN[noun].word}`,
      heading: "Je uitnodiging is klaar",
      body: (invitee: string, noun: Noun) =>
        `${invitee} is ingelogd en heeft een kluis ingesteld. Open het ${NL_NOUN[noun].word} en kies Delen om toegang te geven.`,
      why: (noun: Noun) => `Die stap gebeurt in jouw browser, want alleen jij hebt de sleutels van het ${NL_NOUN[noun].word}.`,
      button: (noun: Noun) => `Open het ${NL_NOUN[noun].word}`,
      footnote: (noun: Noun) => `Je krijgt dit omdat je diegene uitnodigde voor een ${NL_NOUN[noun].word}.`,
    },
    given: {
      subject: (owner: string, noun: Noun) => `${owner} heeft een Tessil-${NL_NOUN[noun].word} met je gedeeld`,
      heading: (noun: Noun) => `Er is een ${NL_NOUN[noun].word} met je gedeeld`,
      body: (owner: string, noun: Noun) =>
        `${owner} heeft je toegang gegeven tot een ${NL_NOUN[noun].word}. Open je ${NL_NOUN[noun].plural} en accepteer het om ${noun === "form" ? "de inzendingen" : "de gestuurde bestanden"} te zien.`,
      button: (noun: Noun) => `Bekijk je ${NL_NOUN[noun].plural}`,
      footnote: (owner: string) => `Ken je ${owner} niet? Dan kun je het daar afwijzen.`,
    },
    response: {
      subject: "Een nieuwe inzending op een van je Tessil-formulieren",
      heading: "Er is een nieuwe inzending",
      body: "Iemand heeft een van je formulieren ingevuld. Open het om de antwoorden te lezen.",
      why: "We kunnen niet zeggen welk formulier of wat er is geantwoord: beide zijn versleuteld en alleen jij kunt ze lezen.",
      button: "Open het formulier",
      footnote: "Hooguit één per formulier per uur. De eigenaar van het formulier kan ze uitzetten in de instellingen.",
    },
    files: {
      subject: "Nieuwe bestanden in een van je Tessil-portalen",
      heading: "Er zijn nieuwe bestanden",
      body: "Iemand heeft bestanden gestuurd via een van je portalen. Open het om te zien wat er binnenkwam.",
      why: "We kunnen niet zeggen welk portaal of wat er is gestuurd: beide zijn versleuteld en alleen jij kunt ze lezen.",
      button: "Open het portaal",
      footnote: "Hooguit één per portaal per uur. De eigenaar van het portaal kan ze uitzetten in de instellingen.",
    },
  },
};

export const emailCopy: Record<MailLocale, typeof en> = { en, nl };
