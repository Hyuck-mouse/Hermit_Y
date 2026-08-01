from typing import List, Dict, Any, Optional
from .store import KnowledgeStore
import re


class KnowledgeRetriever:
    def __init__(self, store: KnowledgeStore):
        self.store = store

    def search(self, query: str, max_results: int = 5) -> List[Dict[str, Any]]:
        results = []
        query_lower = query.lower()
        
        for entry_id in self.store.list_entries():
            entry = self.store.load_entry(entry_id)
            if entry:
                score = self._calculate_score(entry, query_lower)
                if score > 0:
                    entry["_score"] = score
                    results.append(entry)
        
        results.sort(key=lambda x: x["_score"], reverse=True)
        return results[:max_results]

    def _calculate_score(self, entry: Dict[str, Any], query: str) -> int:
        score = 0
        
        if "title" in entry and query in entry["title"].lower():
            score += 10
        
        if "content" in entry and query in entry["content"].lower():
            score += 5
        
        if "tags" in entry:
            for tag in entry["tags"]:
                if query in tag.lower():
                    score += 3
        
        if "keywords" in entry:
            for keyword in entry["keywords"]:
                if query in keyword.lower():
                    score += 2
        
        return score

    def get_by_category(self, category: str) -> List[Dict[str, Any]]:
        return self.store.search_by_tag(category)

    def get_vulnerability_info(self, vuln_type: str) -> Optional[Dict[str, Any]]:
        results = self.search(vuln_type)
        if results:
            return results[0]
        return None

    def get_ctf_solution(self, challenge_type: str) -> Optional[Dict[str, Any]]:
        results = self.search(f"ctf {challenge_type}")
        if results:
            return results[0]
        return None

    def suggest_attack_vector(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        queries = []
        
        if "tech" in target_info:
            for tech in target_info["tech"]:
                queries.append(f"{tech} vulnerability")
        
        if "port" in target_info:
            for port in target_info["port"]:
                queries.append(f"port {port} exploit")
        
        results = []
        for query in queries:
            results.extend(self.search(query, max_results=2))
        
        seen_ids = set()
        unique_results = []
        for r in results:
            entry_id = r.get("id", str(id(r)))
            if entry_id not in seen_ids:
                seen_ids.add(entry_id)
                unique_results.append(r)
        
        return unique_results[:5]

