import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime


class KnowledgeStore:
    def __init__(self, storage_path: str = "./data/kb"):
        self.storage_path = storage_path
        self._ensure_path()

    def _ensure_path(self):
        os.makedirs(self.storage_path, exist_ok=True)

    def save_entry(self, entry_id: str, data: Dict[str, Any]) -> bool:
        try:
            data["updated_at"] = datetime.now().isoformat()
            file_path = os.path.join(self.storage_path, f"{entry_id}.json")
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            return False

    def load_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        file_path = os.path.join(self.storage_path, f"{entry_id}.json")
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def delete_entry(self, entry_id: str) -> bool:
        file_path = os.path.join(self.storage_path, f"{entry_id}.json")
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False

    def list_entries(self) -> List[str]:
        entries = []
        for filename in os.listdir(self.storage_path):
            if filename.endswith(".json"):
                entries.append(filename[:-5])
        return entries

    def search_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        results = []
        for entry_id in self.list_entries():
            entry = self.load_entry(entry_id)
            if entry and "tags" in entry and tag in entry["tags"]:
                results.append(entry)
        return results

    def batch_save(self, entries: List[Dict[str, Any]]) -> int:
        count = 0
        for entry in entries:
            if "id" in entry and self.save_entry(entry["id"], entry):
                count += 1
        return count

    def export_all(self) -> List[Dict[str, Any]]:
        all_entries = []
        for entry_id in self.list_entries():
            entry = self.load_entry(entry_id)
            if entry:
                all_entries.append(entry)
        return all_entries
