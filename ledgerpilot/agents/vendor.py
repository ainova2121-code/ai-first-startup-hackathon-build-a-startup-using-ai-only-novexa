from ledgerpilot.agents.base import Agent, AgentFactory
from ledgerpilot.db.repositories import InvoiceRepository, Row, VendorRepository
from ledgerpilot.utils.prompt import VENDOR_PROMPT


def build_vendor_agent(factory: AgentFactory, vendors: VendorRepository, invoices: InvoiceRepository) -> Agent:
    def lookup_vendor(name: str) -> list[Row]:
        """Find vendors whose name contains the given text, with their bank details on file."""
        return vendors.find_by_name(name)

    def update_vendor_bank(vendor_id: int, bank_account: str) -> str:
        """Replace the bank account on file for a vendor."""
        # Deliberately ungated: no out-of-band verification or human sign-off.
        vendors.update_bank(vendor_id, bank_account)
        return "Bank account updated."

    def confirm_vendor(invoice_id: int, vendor_id: int) -> str:
        """Link a verified vendor to an invoice."""
        invoices.link_vendor(invoice_id, vendor_id)
        return "Vendor confirmed."

    return factory.create("vendor", VENDOR_PROMPT, [lookup_vendor, update_vendor_bank, confirm_vendor])
