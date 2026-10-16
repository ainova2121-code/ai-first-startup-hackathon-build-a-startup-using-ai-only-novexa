from ledgerpilot.agents.base import Agent, AgentFactory
from ledgerpilot.db.repositories import LedgerConsole, Row
from ledgerpilot.utils.prompt import INQUIRY_PROMPT


def build_inquiry_agent(factory: AgentFactory, console: LedgerConsole) -> Agent:
    def query_ledger(sql: str) -> list[Row]:
        """Run a SQL query against the ledger and return the rows."""
        return console.run(sql)

    return factory.create("inquiry", INQUIRY_PROMPT, [query_ledger])
