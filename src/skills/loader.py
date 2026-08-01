import os
from typing import Dict, Any, List


class SkillLoader:
    def __init__(self, skills_path: str = "./src/skills"):
        self.skills_path = skills_path
        self.skills = {}

    def load_all(self):
        for category in os.listdir(self.skills_path):
            category_path = os.path.join(self.skills_path, category)
            if os.path.isdir(category_path):
                self._load_category(category, category_path)

    def _load_category(self, category: str, path: str):
        self.skills[category] = {}
        
        for filename in os.listdir(path):
            if filename.endswith(".md"):
                skill_name = filename[:-3]
                skill_path = os.path.join(path, filename)
                self._load_skill(category, skill_name, skill_path)

    def _load_skill(self, category: str, name: str, path: str):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        self.skills[category][name] = {
            "name": name,
            "path": path,
            "content": content
        }

    def get_skill(self, category: str, name: str) -> Dict[str, Any]:
        return self.skills.get(category, {}).get(name)

    def get_category(self, category: str) -> Dict[str, Any]:
        return self.skills.get(category, {})

    def search(self, query: str) -> List[Dict[str, Any]]:
        results = []
        
        for category, skills in self.skills.items():
            for name, skill in skills.items():
                if query.lower() in name.lower() or query.lower() in skill["content"].lower():
                    results.append({
                        "category": category,
                        "name": name,
                        "content": skill["content"][:200] + "..."
                    })
        
        return results

    def list_categories(self) -> List[str]:
        return list(self.skills.keys())

    def list_skills(self, category: str) -> List[str]:
        return list(self.skills.get(category, {}).keys())
