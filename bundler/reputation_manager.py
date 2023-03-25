from typing import Dict
from dataclasses import field
from enum import Enum

MIN_INCLUSION_RATE_DENOMINATOR = 10
THROTTLING_SLACK = 10
BAN_SLACK = 50

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
        ops_seen,
        ops_included,
        status,
    ):
        self.ops_seen = ops_seen
        self.ops_included = ops_included
        self.status = status

class ReputationManager:
    entities_reputation = {}
    white_list: list = field(default_factory=list[str])
    black_list: list = field(default_factory=list[str])

    def get_reputation_entry(self, entity:str):
        if entity not in self.entities_reputation:
            self.entities_reputation[entity] = ReputationEntry()

        return self.entities_reputation[entity]
    
    def update_seen_status(self, entity:str):
        if entity not in self.entities_reputation:
            self.entities_reputation[entity] = ReputationEntry(0, 0, ReputationStatus.OK)
        ops_seen = self.entities_reputation[entity].ops_seen
        self.entities_reputation[entity].ops_seen = ops_seen + 1
    
    def update_included_status(self, entity:str):
        if entity not in self.entities_reputation:
            self.entities_reputation[entity] = ReputationEntry(0, 0, ReputationStatus.OK)
        ops_included = self.entities_reputation[entity].ops_included
        self.entities_reputation[entity].ops_included = ops_included + 1
    
    def is_whitelisted(self, entity:str):
        return entity in self.white_list
    
    def is_blacklisted(self, entity:str):
        return entity in self.black_list
    
    def get_status(self, entity: str):
        if entity not in self.entities_reputation:
            return ReputationStatus.OK
        
        reputation_entry = self.entities_reputation[entity]
        min_expected_included = reputation_entry.ops_seen // MIN_INCLUSION_RATE_DENOMINATOR
        if min_expected_included <= reputation_entry.ops_included + THROTTLING_SLACK:
            return ReputationStatus.OK
        elif min_expected_included <= reputation_entry.ops_included + BAN_SLACK:
            return ReputationStatus.THROTTLED
        else:
            return ReputationStatus.BANNED 