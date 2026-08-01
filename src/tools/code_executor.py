import subprocess
import sys
from typing import Dict, Any

# 多语言代码执行器 RCE
class CodeExecutor:
    def __init__(self):
        self.execution_history = []  # 初始化一个空列表，用来记录每次代码执行的历史结果

    # 定义执行 Python 代码的方法，接收代码字符串和超时时间，返回字典
    def execute_python(self, code: str, timeout: int = 30) -> Dict[str, Any]:
        result = {
            "success": False,
            "output": "",
            "error": "",
            "type": "python"
        }

        try:
            # 用subprocess执行，避免exec作用域问题
            completed = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            result["success"] = completed.returncode == 0
            result["output"] = completed.stdout
            result["error"] = completed.stderr
        except subprocess.TimeoutExpired:
            result["error"] = "Command timed out"
        except Exception as e:
            result["error"] = str(e)

        self.execution_history.append(result)
        return result

    #  定义执行 Bash 命令的方法
    def execute_bash(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        result = {
            "success": False,
            "output": "",
            "error": "",
            "type": "bash"
        }
        
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            result["success"] = completed.returncode == 0
            result["output"] = completed.stdout
            result["error"] = completed.stderr
        except subprocess.TimeoutExpired:
            result["error"] = "Command timed out"
        except Exception as e:
            result["error"] = str(e)
        
        self.execution_history.append(result)
        return result

    # 定义执行 JS 代码的方法
    def execute_javascript(self, code: str, timeout: int = 30) -> Dict[str, Any]:
        result = {
            "success": False,
            "output": "",
            "error": "",
            "type": "javascript"
        }
        
        try:
            completed = subprocess.run(
                ["node", "-e", code],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            result["success"] = completed.returncode == 0
            result["output"] = completed.stdout
            result["error"] = completed.stderr
        except subprocess.TimeoutExpired:
            result["error"] = "Command timed out"
        except FileNotFoundError:
            result["error"] = "Node.js not installed"
        except Exception as e:
            result["error"] = str(e)
        
        self.execution_history.append(result)
        return result

    # 定义 SQL 执行方法，支持指定数据库类型和路径（建议独立分出去sqlmap）
    def execute_sql(self, query: str, db_type: str = "sqlite", db_path: str = ":memory:") -> Dict[str, Any]:
        result = {
            "success": False,
            "output": [],
            "error": "",
            "type": "sql"
        }
        
        try:
            if db_type == "sqlite":
                import sqlite3
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute(query)
                conn.commit()
                
                if query.strip().upper().startswith("SELECT"):
                    result["output"] = cursor.fetchall()
                
                conn.close()
                result["success"] = True
            else:
                result["error"] = f"Unsupported database type: {db_type}"
        except Exception as e:
            result["error"] = str(e)
        
        self.execution_history.append(result)
        return result

    # 定义获取历史记录的方法
    def get_history(self) -> list:
        return self.execution_history

    # 定义清空历史记录的方法
    def clear_history(self):
        self.execution_history = []
