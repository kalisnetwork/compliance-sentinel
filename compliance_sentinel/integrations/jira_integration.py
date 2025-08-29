"""Jira integration for automated security ticket creation and tracking."""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import base64

from .ticket_manager import TicketConfig


logger = logging.getLogger(__name__)


class JiraIntegration:
    """Jira integration for security ticket management."""
    
    def __init__(self, config: TicketConfig):
        """Initialize Jira integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Set up authentication
        self._setup_authentication()
        
        # Validate connection
        self._validate_connection()
    
    def _setup_authentication(self):
        """Set up Jira authentication."""
        if self.config.api_token:
            # Use API token authentication (recommended)
            auth_string = f"{self.config.username}:{self.config.api_token}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {encoded_auth}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
        elif self.config.username and self.config.password:
            # Use basic authentication (less secure)
            self.session.auth = (self.config.username, self.config.password)
            self.session.headers.update({
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
        else:
            raise ValueError("Jira authentication credentials not provided")
    
    def _validate_connection(self):
        """Validate Jira connection and permissions."""
        try:
            response = self.session.get(f"{self.config.api_url}/rest/api/3/myself")
            response.raise_for_status()
            
            user_info = response.json()
            self.logger.info(f"Connected to Jira as {user_info.get('displayName', 'Unknown')}")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to connect to Jira: {e}")
            raise
    
    def create_ticket(self, 
                     title: str,
                     description: str,
                     priority: str = "Medium",
                     assignee: str = "",
                     labels: List[str] = None,
                     due_date: datetime = None,
                     custom_fields: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Create a new Jira ticket."""
        
        try:
            # Prepare issue data
            issue_data = {
                "fields": {
                    "project": {"key": self.config.project_key},
                    "summary": title,
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": description
                                    }
                                ]
                            }
                        ]
                    },
                    "issuetype": {"name": "Bug"},  # Default to Bug type for security issues
                    "priority": {"name": self._map_priority(priority)}
                }
            }
            
            # Add assignee if specified
            if assignee:
                issue_data["fields"]["assignee"] = {"accountId": assignee}
            
            # Add labels if specified
            if labels:
                issue_data["fields"]["labels"] = labels
            
            # Add due date if specified
            if due_date:
                issue_data["fields"]["duedate"] = due_date.strftime("%Y-%m-%d")
            
            # Add custom fields
            if custom_fields:
                issue_data["fields"].update(custom_fields)
            
            # Create the issue
            response = self.session.post(
                f"{self.config.api_url}/rest/api/3/issue",
                json=issue_data
            )
            response.raise_for_status()
            
            created_issue = response.json()
            
            # Return ticket information
            return {
                "id": created_issue["key"],
                "url": f"{self.config.api_url}/browse/{created_issue['key']}",
                "internal_id": created_issue["id"]
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create Jira ticket: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response: {e.response.text}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error creating Jira ticket: {e}")
            return None
    
    def update_ticket_status(self, ticket_id: str, status: str, resolution_notes: str = "") -> bool:
        """Update ticket status and add resolution notes."""
        try:
            # Get available transitions
            transitions_response = self.session.get(
                f"{self.config.api_url}/rest/api/3/issue/{ticket_id}/transitions"
            )
            transitions_response.raise_for_status()
            
            transitions = transitions_response.json()["transitions"]
            
            # Find the appropriate transition
            target_transition = None
            status_mapping = {
                "in_progress": ["In Progress", "Start Progress"],
                "resolved": ["Resolve Issue", "Done", "Resolved"],
                "closed": ["Close Issue", "Closed"],
                "wont_fix": ["Won't Fix", "Won't Do"]
            }
            
            target_names = status_mapping.get(status, [status])
            
            for transition in transitions:
                if transition["name"] in target_names:
                    target_transition = transition
                    break
            
            if not target_transition:
                self.logger.warning(f"No transition found for status '{status}' on ticket {ticket_id}")
                return False
            
            # Prepare transition data
            transition_data = {
                "transition": {"id": target_transition["id"]}
            }
            
            # Add resolution notes as comment
            if resolution_notes:
                transition_data["update"] = {
                    "comment": [
                        {
                            "add": {
                                "body": {
                                    "type": "doc",
                                    "version": 1,
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": resolution_notes
                                                }
                                            ]
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            
            # Execute transition
            response = self.session.post(
                f"{self.config.api_url}/rest/api/3/issue/{ticket_id}/transitions",
                json=transition_data
            )
            response.raise_for_status()
            
            self.logger.info(f"Updated Jira ticket {ticket_id} status to {status}")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to update Jira ticket {ticket_id}: {e}")
            return False
    
    def get_ticket(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        """Get ticket details from Jira."""
        try:
            response = self.session.get(
                f"{self.config.api_url}/rest/api/3/issue/{ticket_id}",
                params={"fields": "summary,status,priority,assignee,created,updated,resolutiondate,labels"}
            )
            response.raise_for_status()
            
            issue = response.json()
            fields = issue["fields"]
            
            # Map Jira status to our status enum
            jira_status = fields["status"]["name"].lower()
            status_mapping = {
                "open": "open",
                "to do": "open",
                "in progress": "in_progress",
                "done": "resolved",
                "resolved": "resolved",
                "closed": "closed"
            }
            
            mapped_status = status_mapping.get(jira_status, "open")
            
            return {
                "id": issue["key"],
                "title": fields["summary"],
                "status": mapped_status,
                "priority": fields["priority"]["name"].lower() if fields["priority"] else "medium",
                "assignee": fields["assignee"]["displayName"] if fields["assignee"] else "",
                "created_at": fields["created"],
                "updated_at": fields["updated"],
                "resolved_at": fields.get("resolutiondate"),
                "labels": fields.get("labels", []),
                "url": f"{self.config.api_url}/browse/{issue['key']}"
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Jira ticket {ticket_id}: {e}")
            return None
    
    def search_tickets(self, jql: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Search for tickets using JQL."""
        try:
            search_data = {
                "jql": jql,
                "maxResults": max_results,
                "fields": ["summary", "status", "priority", "assignee", "created", "updated", "labels"]
            }
            
            response = self.session.post(
                f"{self.config.api_url}/rest/api/3/search",
                json=search_data
            )
            response.raise_for_status()
            
            search_results = response.json()
            tickets = []
            
            for issue in search_results["issues"]:
                fields = issue["fields"]
                
                tickets.append({
                    "id": issue["key"],
                    "title": fields["summary"],
                    "status": fields["status"]["name"],
                    "priority": fields["priority"]["name"] if fields["priority"] else "Medium",
                    "assignee": fields["assignee"]["displayName"] if fields["assignee"] else "",
                    "created_at": fields["created"],
                    "updated_at": fields["updated"],
                    "labels": fields.get("labels", []),
                    "url": f"{self.config.api_url}/browse/{issue['key']}"
                })
            
            return tickets
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to search Jira tickets: {e}")
            return []
    
    def add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add a comment to a Jira ticket."""
        try:
            comment_data = {
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": comment
                                }
                            ]
                        }
                    ]
                }
            }
            
            response = self.session.post(
                f"{self.config.api_url}/rest/api/3/issue/{ticket_id}/comment",
                json=comment_data
            )
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to add comment to Jira ticket {ticket_id}: {e}")
            return False
    
    def get_project_info(self) -> Optional[Dict[str, Any]]:
        """Get project information."""
        try:
            response = self.session.get(
                f"{self.config.api_url}/rest/api/3/project/{self.config.project_key}"
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Jira project info: {e}")
            return None
    
    def _map_priority(self, priority: str) -> str:
        """Map generic priority to Jira priority names."""
        priority_mapping = {
            "critical": "Highest",
            "high": "High", 
            "medium": "Medium",
            "low": "Low"
        }
        
        return priority_mapping.get(priority.lower(), "Medium")
    
    def get_security_tickets_jql(self) -> str:
        """Generate JQL for finding security-related tickets."""
        labels = " OR ".join([f'labels = "{label}"' for label in self.config.default_labels])
        return f'project = "{self.config.project_key}" AND ({labels}) ORDER BY created DESC'
    
    def bulk_update_tickets(self, ticket_ids: List[str], updates: Dict[str, Any]) -> Dict[str, bool]:
        """Bulk update multiple tickets."""
        results = {}
        
        for ticket_id in ticket_ids:
            try:
                response = self.session.put(
                    f"{self.config.api_url}/rest/api/3/issue/{ticket_id}",
                    json={"fields": updates}
                )
                response.raise_for_status()
                results[ticket_id] = True
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Failed to update Jira ticket {ticket_id}: {e}")
                results[ticket_id] = False
        
        return results