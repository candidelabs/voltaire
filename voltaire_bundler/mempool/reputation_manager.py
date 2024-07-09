import asyncio
import logging
import math
from dataclasses import dataclass
from enum import Enum

MIN_INCLUSION_RATE_DENOMINATOR = 10
THROTTLING_SLACK = 10
BAN_SLACK = 50

REPUTATION_BACKOFF_INTERVAL = 3600  # hourly


class ReputationStatus(Enum):
    OK = 1
    THROTTLED = 2
    BANNED = 3


@dataclass
class ReputationEntry:
    ops_seen: int = 0
    ops_included: int = 0


class ReputationManager:
    entities_reputation: dict[str, ReputationEntry] = {}
    white_list: list = []
    black_list: list = []

    def __init__(self) -> None:
        asyncio.ensure_future(self.execute_reputation_cron_job())

    async def execute_reputation_cron_job(self) -> None:
        while True:
            self._reputation_backoff_cron_job()
            await asyncio.sleep(REPUTATION_BACKOFF_INTERVAL)

    def _reputation_backoff_cron_job(self) -> None:
        logging.info("Updating reputation entries")
        entities_to_delete = []
        for entity_address, entry in self.entities_reputation.items():
            entry.ops_seen = math.floor(entry.ops_seen * 23 / 24)
            entry.ops_included = math.floor(entry.ops_included * 23 / 24)
            if entry.ops_seen == 0 and entry.ops_included == 0:
                entities_to_delete.append(entity_address)
        for entity in entities_to_delete:
            del self.entities_reputation[entity]

    def get_reputation_entry(self, entity: str) -> ReputationEntry | None:
        entity_address = entity.lower()
        if entity_address not in self.entities_reputation:
            return None
        return self.entities_reputation[entity_address]

    def update_seen_status(self, entity: str, modifier: int = 1) -> None:
        entity_address = entity.lower()
        if entity_address not in self.entities_reputation:
            self.entities_reputation[entity_address] = ReputationEntry()
        self.entities_reputation[entity_address].ops_seen += modifier

    def update_included_status(self, entity: str, modifier: int = 1) -> None:
        entity_address = entity.lower()
        if entity_address not in self.entities_reputation:
            self.entities_reputation[entity_address] = ReputationEntry()
        self.entities_reputation[entity_address].ops_included += modifier

    def ban_entity(self, entity: str) -> None:
        self.entities_reputation[entity.lower()] = ReputationEntry(10000, 0)

    def is_whitelisted(self, entity: str) -> bool:
        return entity.lower() in self.white_list

    def is_blacklisted(self, entity: str) -> bool:
        return entity.lower() in self.black_list

    def get_status(self, entity: str) -> ReputationStatus:
        entity_address = entity.lower()
        if entity_address not in self.entities_reputation:
            return ReputationStatus.OK

        reputation_entry = self.entities_reputation[entity_address]
        min_expected_included = (
            reputation_entry.ops_seen // MIN_INCLUSION_RATE_DENOMINATOR
        )
        if (
            min_expected_included <=
            (reputation_entry.ops_included + THROTTLING_SLACK)
        ):
            return ReputationStatus.OK
        elif min_expected_included <= reputation_entry.ops_included + BAN_SLACK:
            return ReputationStatus.THROTTLED
        else:
            return ReputationStatus.BANNED

    def set_reputation(
        self,
        entitiy: str,
        ops_seen: int,
        ops_included: int,
    ) -> None:
        reputation_entry = ReputationEntry(ops_seen, ops_included)
        self.entities_reputation[entitiy.lower()] = reputation_entry

    def get_entities_reputation_json(self) -> list[dict[str, str]]:
        entities_reputation_json = []
        for entity_address in self.entities_reputation.keys():
            entry = entity_reputation_json = self.entities_reputation[
                entity_address]

            status = self.get_status(entity_address)
            if status == ReputationStatus.OK:
                status_str = "ok"
            elif status == ReputationStatus.THROTTLED:
                status_str = "throttled"
            else:
                status_str = "banned"

            entity_reputation_json = {
                "opsSeen": entry.ops_seen,
                "opsIncluded": entry.ops_included,
                "status": status_str,
                "address": entity_address
            }
            entities_reputation_json.append(entity_reputation_json)

        return entities_reputation_json

    def clear_all_repuations(self) -> None:
        self.entities_reputation.clear()
