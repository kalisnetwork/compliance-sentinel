"""Asana integration for security task management and assignment."""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from .ticket_manager import TicketConfig


logger = logging.getLogger(__name__)


class AsanaIntegration:
    """Asana integration for security task management."""
    
    def __init__(self, config: TicketConfig):
        """Initialize Asana integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Set up authentication
        self._setup_authentication()
        
        # Validate connection and get workspace info
        self._validate_connection()
    
    def _setup_authentication(self):
        """Set up Asana authentication."""
        if not self.config.api_token:
            raise ValueError("Asana API token not provided")
        
        self.session.headers.update({
            'Authorization': f'Bearer {self.config.api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def _validate_connection(self):
        """Validate Asana connection and get user info."""
        try:
            response = self.session.get("https://app.asana.com/api/1.0/users/me")
            response.raise_for_status()
            
            user_info = response.json()["data"]
            self.logger.info(f"Connected to Asana as {user_info.get('name', 'Unknown')}")
            
            # Get workspace info if workspace_id is provided
            if self.config.workspace_id:
                self._validate_workspace()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to connect to Asana: {e}")
            raise
    
    def _validate_workspace(self):
        """Validate workspace access."""
        try:
            response = self.session.get(f"https://app.asana.com/api/1.0/workspaces/{self.config.workspace_id}")
            response.raise_for_status()
            
            workspace_info = response.json()["data"]
            self.logger.info(f"Using Asana workspace: {workspace_info.get('name', 'Unknown')}")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to access Asana workspace {self.config.workspace_id}: {e}")
            raise
    
    def create_ticket(self, 
                     title: str,
                     description: str,
                     priority: str = "Medium",
                     assignee: str = "",
                     labels: List[str] = None,
                     due_date: datetime = None,
                     custom_fields: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Create a new Asana task."""
        
        try:
            # Prepare task data
            task_data = {
                "data": {
                    "name": title,
                    "notes": description,
                    "projects": [self.config.project_key] if self.config.project_key else [],
                    "workspace": self.config.workspace_id
                }
            }
            
            # Add assignee if specified
            if assignee:
                task_data["data"]["assignee"] = assignee
            
            # Add due date if specified
            if due_date:
                task_data["data"]["due_on"] = due_date.strftime("%Y-%m-%d")
            
            # Add tags (Asana's equivalent of labels)
            if labels:
                # First, ensure tags exist and get their GIDs
                tag_gids = []
                for label in labels:
                    tag_gid = self._get_or_create_tag(label)
                    if tag_gid:
                        tag_gids.append(tag_gid)
                
                if tag_gids:
                    task_data["data"]["tags"] = tag_gids
            
            # Create the task
            response = self.session.post(
                "https://app.asana.com/api/1.0/tasks",
                json=task_data
            )
            response.raise_for_status()
            
            created_task = response.json()["data"]
            
            # Set priority using custom fields if available
            if priority and priority.lower() != "medium":
                self._set_task_priority(created_task["gid"], priority)
            
            # Return task information
            return {
                "id": created_task["gid"],
                "url": created_task.get("permalink_url", f"https://app.asana.com/0/{self.config.project_key}/{created_task['gid']}"),
                "name": created_task["name"]
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create Asana task: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response: {e.response.text}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error creating Asana task: {e}")
            return None
    
    def update_ticket_status(self, task_id: str, status: str, resolution_notes: str = "") -> bool:
        """Update task status and add resolution notes."""
        try:
            # Map status to Asana completion state
            completed = status in ["resolved", "closed"]
            
            # Update task completion status
            update_data = {
                "data": {
                    "completed": completed
                }
            }
            
            response = self.session.put(
                f"https://app.asana.com/api/1.0/tasks/{task_id}",
                json=update_data
            )
            response.raise_for_status()
            
            # Add resolution notes as a comment if provided
            if resolution_notes:
                self.add_comment(task_id, resolution_notes)
            
            self.logger.info(f"Updated Asana task {task_id} status to {status}")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to update Asana task {task_id}: {e}")
            return False
    
    def get_ticket(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task details from Asana."""
        try:
            response = self.session.get(
                f"https://app.asana.com/api/1.0/tasks/{task_id}",
                params={"opt_fields": "name,notes,completed,assignee.name,created_at,modified_at,due_on,tags.name,permalink_url"}
            )
            response.raise_for_status()
            
            task = response.json()["data"]
            
            # Map Asana completion to our status
            status = "resolved" if task.get("completed") else "open"
            
            return {
                "id": task["gid"],
                "title": task["name"],
                "description": task.get("notes", ""),
                "status": status,
                "priority": "medium",  # Asana doesn't have built-in priority
                "assignee": task["assignee"]["name"] if task.get("assignee") else "",
                "created_at": task["created_at"],
                "updated_at": task["modified_at"],
                "due_date": task.get("due_on"),
                "tags": [tag["name"] for tag in task.get("tags", [])],
                "url": task.get("permalink_url", "")
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Asana task {task_id}: {e}")
            return None
    
    def search_tickets(self, project_id: str = None, assignee: str = None, completed: bool = None) -> List[Dict[str, Any]]:
        """Search for tasks in Asana."""
        try:
            params = {
                "opt_fields": "name,completed,assignee.name,created_at,modified_at,tags.name,permalink_url"
            }
            
            # Use project_id or fall back to config
            project_id = project_id or self.config.project_key
            
            if project_id:
                url = f"https://app.asana.com/api/1.0/projects/{project_id}/tasks"
            else:
                url = "https://app.asana.com/api/1.0/tasks"
                params["workspace"] = self.config.workspace_id
            
            if assignee:
                params["assignee"] = assignee
            
            if completed is not None:
                params["completed_since"] = "now" if not completed else None
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            tasks_data = response.json()["data"]
            tasks = []
            
            for task in tasks_data:
                status = "resolved" if task.get("completed") else "open"
                
                tasks.append({
                    "id": task["gid"],
                    "title": task["name"],
                    "status": status,
                    "assignee": task["assignee"]["name"] if task.get("assignee") else "",
                    "created_at": task["created_at"],
                    "updated_at": task["modified_at"],
                    "tags": [tag["name"] for tag in task.get("tags", [])],
                    "url": task.get("permalink_url", "")
                })
            
            return tasks
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to search Asana tasks: {e}")
            return []
    
    def add_comment(self, task_id: str, comment: str) -> bool:
        """Add a comment to an Asana task."""
        try:
            comment_data = {
                "data": {
                    "text": comment,
                    "parent": task_id
                }
            }
            
            response = self.session.post(
                "https://app.asana.com/api/1.0/stories",
                json=comment_data
            )
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to add comment to Asana task {task_id}: {e}")
            return False
    
    def _get_or_create_tag(self, tag_name: str) -> Optional[str]:
        """Get existing tag or create new one."""
        try:
            # Search for existing tag
            response = self.session.get(
                "https://app.asana.com/api/1.0/tags",
                params={"workspace": self.config.workspace_id, "opt_fields": "name"}
            )
            response.raise_for_status()
            
            tags = response.json()["data"]
            
            # Check if tag already exists
            for tag in tags:
                if tag["name"].lower() == tag_name.lower():
                    return tag["gid"]
            
            # Create new tag if it doesn't exist
            tag_data = {
                "data": {
                    "name": tag_name,
                    "workspace": self.config.workspace_id
                }
            }
            
            response = self.session.post(
                "https://app.asana.com/api/1.0/tags",
                json=tag_data
            )
            response.raise_for_status()
            
            new_tag = response.json()["data"]
            return new_tag["gid"]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get or create Asana tag '{tag_name}': {e}")
            return None
    
    def _set_task_priority(self, task_id: str, priority: str):
        """Set task priority using custom fields (if available)."""
        try:
            # This would require custom field setup in Asana
            # For now, we'll add priority as a tag
            priority_tag = f"priority-{priority.lower()}"
            tag_gid = self._get_or_create_tag(priority_tag)
            
            if tag_gid:
                # Add tag to task
                response = self.session.post(
                    f"https://app.asana.com/api/1.0/tasks/{task_id}/addTag",
                    json={"data": {"tag": tag_gid}}
                )
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to set priority for Asana task {task_id}: {e}")
    
    def get_project_info(self) -> Optional[Dict[str, Any]]:
        """Get project information."""
        try:
            if not self.config.project_key:
                return None
            
            response = self.session.get(
                f"https://app.asana.com/api/1.0/projects/{self.config.project_key}",
                params={"opt_fields": "name,notes,created_at,modified_at,team.name,workspace.name"}
            )
            response.raise_for_status()
            
            return response.json()["data"]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Asana project info: {e}")
            return None
    
    def create_project(self, name: str, notes: str = "") -> Optional[str]:
        """Create a new Asana project for security tasks."""
        try:
            project_data = {
                "data": {
                    "name": name,
                    "notes": notes,
                    "workspace": self.config.workspace_id,
                    "privacy_setting": "private_to_team"
                }
            }
            
            response = self.session.post(
                "https://app.asana.com/api/1.0/projects",
                json=project_data
            )
            response.raise_for_status()
            
            project = response.json()["data"]
            return project["gid"]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create Asana project: {e}")
            return None
    
    def get_team_members(self) -> List[Dict[str, Any]]:
        """Get team members for task assignment."""
        try:
            response = self.session.get(
                f"https://app.asana.com/api/1.0/workspaces/{self.config.workspace_id}/users",
                params={"opt_fields": "name,email"}
            )
            response.raise_for_status()
            
            users = response.json()["data"]
            return [
                {
                    "id": user["gid"],
                    "name": user["name"],
                    "email": user.get("email", "")
                }
                for user in users
            ]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Asana team members: {e}")
            return []
    
    def bulk_update_tasks(self, task_ids: List[str], updates: Dict[str, Any]) -> Dict[str, bool]:
        """Bulk update multiple tasks."""
        results = {}
        
        for task_id in task_ids:
            try:
                response = self.session.put(
                    f"https://app.asana.com/api/1.0/tasks/{task_id}",
                    json={"data": updates}
                )
                response.raise_for_status()
                results[task_id] = True
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Failed to update Asana task {task_id}: {e}")
                results[task_id] = False
        
        return results