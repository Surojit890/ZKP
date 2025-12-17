"""Persistence layer.

The backend supports two storage modes:
- MongoDB, when `MONGODB_URI` is set and reachable
- In-memory dictionaries, as a local-dev/test fallback

The rest of the application interacts with storage through this `Storage` class
to avoid mixing database code with HTTP handlers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from pymongo import MongoClient


@dataclass
class Storage:
    mongodb_uri: Optional[str]
    logger: Any

    def __post_init__(self) -> None:
        # Default to in-memory mode until we successfully connect to MongoDB.
        self.mongo_available = False
        self.users_db: Dict[str, Dict[str, Any]] = {}
        self.challenges_db: Dict[str, Dict[str, Any]] = {}

        self._users_collection = None
        self._challenges_collection = None

        if not self.mongodb_uri:
            self.logger.warning("MONGODB_URI not set in environment. Using in-memory storage.")
            return

        try:
            # Short timeout prevents startup hangs when Mongo is unreachable.
            client = MongoClient(self.mongodb_uri, serverSelectionTimeoutMS=5000)
            client.admin.command("ping")
            db = client["zkp_auth"]
            self._users_collection = db["users"]
            self._challenges_collection = db["challenges"]
            self.mongo_available = True
            self.logger.info("Connected to MongoDB")
        except Exception as e:
            self.logger.warning(f"Using in-memory storage: {e}")

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        if self.mongo_available and self._users_collection is not None:
            return self._users_collection.find_one({"username": username})
        return self.users_db.get(username)

    def save_user(self, username: str, user_data: Dict[str, Any]) -> None:
        if self.mongo_available and self._users_collection is not None:
            self._users_collection.update_one({"username": username}, {"$set": user_data}, upsert=True)
        else:
            self.users_db[username] = user_data

    def save_challenge(self, username: str, challenge_data: Dict[str, Any]) -> None:
        if self.mongo_available and self._challenges_collection is not None:
            self._challenges_collection.insert_one(challenge_data)
        else:
            key = f"{username}_{challenge_data['challenge']}"
            self.challenges_db[key] = challenge_data

    def list_users(self):
        if self.mongo_available and self._users_collection is not None:
            return list(self._users_collection.find({}, {"_id": 0}))
        return list(self.users_db.values())
