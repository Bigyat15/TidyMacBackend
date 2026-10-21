export interface Mail {
  to: string;
  subject: string;
  text: string;
}
export interface Mailer {
  send(m: Mail): Promise<void>;
}

/** Development only: keeps messages in memory and prints them. Refused by `loadConfig` in staging/production. */
export class ConsoleMailer implements Mailer {
  outbox: Mail[] = [];
  private print: boolean;
  constructor(print = true) {
    this.print = print;
  }
  async send(m: Mail) {
    this.outbox.push(m);
    if (this.print) console.log(`\n[dev mail] to=${m.to}\n${m.subject}\n${m.text}\n`);
  }
}

export class ResendMailer implements Mailer {
  private apiKey: string;
  private from: string;
  private fetchImpl: typeof fetch;
  constructor(apiKey: string, from: string, fetchImpl: typeof fetch = fetch) {
    this.apiKey = apiKey;
    this.from = from;
    this.fetchImpl = fetchImpl;
  }
  async send(m: Mail) {
    const r = await this.fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: this.from, to: [m.to], subject: m.subject, text: m.text }),
    });
    if (!r.ok) throw new Error(`email provider rejected the message (HTTP ${r.status})`);
  }
}

export const maskEmail = (e: string) => e.replace(/^(.).*(@.*)$/, "$1***$2");
