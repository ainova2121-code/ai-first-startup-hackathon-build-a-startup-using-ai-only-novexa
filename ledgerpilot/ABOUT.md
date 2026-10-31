# LedgerPilot

An accounts-payable department run by AI agents. A vendor emails an invoice, and five agents take it from inbox to payment: intake reads the invoice and records it, vendor confirms who is being paid, matching checks it against the purchase order and proof of delivery, approval signs it off, and payment pays it.

A sixth agent answers vendors in a supplier portal, looking up their own invoices and payments in the ledger.

It runs on real invoices filed in the FCC political public file, with synthetic bank details, and talks to any OpenAI-compatible model.
