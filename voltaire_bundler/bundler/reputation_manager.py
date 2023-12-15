import asyncio
import logging
import math
from dataclasses import field
from enum import Enum

MIN_INCLUSION_RATE_DENOMINATOR = 10
THROTTLING_SLACK = 10
BAN_SLACK = 50

REPUTATION_BACKOFF_INTERVAL = 3600  # hourly


class ReputationStatus(Enum):
    OK = 1
    THROTTLED = 2
    BANNED = 3


class ReputationEntry:
    ops_seen: int
    ops_included: int
    status: ReputationStatus

    def __init__(
        self,
        ops_seen: int,
        ops_included: int,
        status: ReputationStatus,
    ):
        self.ops_seen = ops_seen
        self.ops_included = ops_included
        self.status = status

    def get_reputation_entry_json(self):
        return {
            "ops_seen": self.ops_seen,
            "ops_included": self.ops_included,
            "status": self.status.value,
        }


class ReputationManager:
    entities_reputation: dict[str, ReputationEntry] = {}
    white_list: list = field(default_factory=list[str])
    black_list: list = field(default_factory=list[str])

    def __init__(self):
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

    def get_reputation_entry(self, entity_address: str):
        if entity_address not in self.entities_reputation:
            self.entities_reputation[entity_address] = ReputationEntry(
                0, 0, ReputationStatus.OK
            )

        return self.entities_reputation[entity_address]

    def update_seen_status(self, entity: str):
        if entity not in self.entities_reputation:
            self.entities_reputation[entity] = ReputationEntry(
                0, 0, ReputationStatus.OK
            )
        ops_seen = self.entities_reputation[entity].ops_seen
        self.entities_reputation[entity].ops_seen = ops_seen + 1

    def update_included_status(self, entity: str):
        if entity not in self.entities_reputation:
            self.entities_reputation[entity] = ReputationEntry(
                0, 0, ReputationStatus.OK
            )
        ops_included = self.entities_reputation[entity].ops_included
        self.entities_reputation[entity].ops_included = ops_included + 1

    def ban_entity(self, entity: str):
        self.entities_reputation[entity] = ReputationEntry(
            100, 0, ReputationStatus.BANNED
        )

    def is_whitelisted(self, entity: str):
        return entity in self.white_list

    def is_blacklisted(self, entity: str):
        return entity in self.black_list

    def get_status(self, entity: str):
        if entity not in self.entities_reputation:
            return ReputationStatus.OK

        reputation_entry = self.entities_reputation[entity]
        min_expected_included = (
            reputation_entry.ops_seen // MIN_INCLUSION_RATE_DENOMINATOR
        )
        if (
            min_expected_included
            <= reputation_entry.ops_included + THROTTLING_SLACK
        ):
            return ReputationStatus.OK
        elif (
            min_expected_included <= reputation_entry.ops_included + BAN_SLACK
        ):
            return ReputationStatus.THROTTLED
        else:
            return ReputationStatus.BANNED

    def set_reputation(
        self, entitiy: str, ops_seen: int, ops_included: int, status: int
    ):
        reputation_entry = ReputationEntry(ops_seen, ops_included, status)
        self.entities_reputation[entitiy] = reputation_entry

    def get_entities_reputation_json(self):
        entities_reputation_json = {}
        for entity_address in self.entities_reputation.keys():
            entities_reputation_json[
                entity_address
            ] = self.entities_reputation[
                entity_address
            ].get_reputation_entry_json()

        return entities_reputation_json
