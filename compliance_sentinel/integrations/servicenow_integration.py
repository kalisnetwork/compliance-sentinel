"""ServiceNow integration for enterprise security incident management."""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import base64

from .ticket_manager import TicketConfig


logger = logging.getLogger(__name__)


class ServiceNowIntegration:
    """ServiceNow integration for enterprise security incident management."""
    
    def __init__(self, config: TicketConfig):
        """Initialize ServiceNow integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Set up authentication
        self._setup_authentication()
        
        # Validate connection
        self._validate_connection()
    
    def _setup_authentication(self):
        """Set up ServiceNow authentication."""
        if self.config.username and self.config.password:
            # Use basic authentication
            auth_string = f"{self.config.username}:{self.config.password}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {encoded_auth}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
        elif self.config.api_token:
            # Use OAuth token
            self.session.headers.update({
                'Authorization': f'Bearer {self.config.api_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            })
        else:
            raise ValueError("ServiceNow authentication credentials not provided")
    
    def _validate_connection(self):
        """Validate ServiceNow connection."""
        try:
            # Test connection with a simple API call
            response = self.session.get(f"{self.config.api_url}/api/now/table/sys_user/me")
            response.raise_for_status()
            
            user_info = response.json()["result"]
            self.logger.info(f"Connected to ServiceNow as {user_info.get('name', 'Unknown')}")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to connect to ServiceNow: {e}")
            raise
    
    def create_ticket(self, 
                     title: str,
                     description: str,
                     priority: str = "Medium",
                     assignee: str = "",
                     labels: List[str] = None,
                     due_date: datetime = None,
                     custom_fields: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Create a new ServiceNow incident."""
        
        try:
            # Prepare incident data
            incident_data = {
                "short_description": title,
                "description": description,
                "category": "Security",
                "subcategory": "Security Incident",
                "priority": self._map_priority(priority),
                "urgency": self._map_priority_to_urgency(priority),
                "impact": self._map_priority_to_impact(priority),
                "state": "1",  # New
                "caller_id": self.config.username
            }
            
            # Add assignment group or assignee
            if assignee:
                # Try to find user by username/email
                user_sys_id = self._find_user_sys_id(assignee)
                if user_sys_id:
                    incident_data["assigned_to"] = user_sys_id
            
            # Add work notes with labels/tags
            if labels:
                work_notes = f"Security Labels: {', '.join(labels)}"
                incident_data["work_notes"] = work_notes
            
            # Add custom fields
            if custom_fields:
                incident_data.update(custom_fields)
            
            # Create the incident
            response = self.session.post(
                f"{self.config.api_url}/api/now/table/incident",
                json=incident_data
            )
            response.raise_for_status()
            
            created_incident = response.json()["result"]
            
            # Return incident information
            return {
                "id": created_incident["number"],
                "sys_id": created_incident["sys_id"],
                "url": f"{self.config.api_url}/nav_to.do?uri=incident.do?sys_id={created_incident['sys_id']}"
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create ServiceNow incident: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response: {e.response.text}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error creating ServiceNow incident: {e}")
            return None
    
    def update_ticket_status(self, ticket_id: str, status: str, resolution_notes: str = "") -> bool:
        """Update incident status and add resolution notes."""
        try:
            # Find incident by number
            incident_sys_id = self._find_incident_sys_id(ticket_id)
            if not incident_sys_id:
                self.logger.error(f"ServiceNow incident {ticket_id} not found")
                return False
            
            # Map status to ServiceNow state
            state_mapping = {
                "open": "1",           # New
                "in_progress": "2",    # In Progress
                "resolved": "6",       # Resolved
                "closed": "7",         # Closed
                "wont_fix": "8"        # Canceled
            }
            
            snow_state = state_mapping.get(status, "1")
            
            # Prepare update data
            update_data = {
                "state": snow_state
            }
            
            # Add resolution information if resolving/closing
            if status in ["resolved", "closed"]:
                update_data["close_code"] = "Solved (Permanently)"
                if resolution_notes:
                    update_data["close_notes"] = resolution_notes
            
            # Add work notes if provided
            if resolution_notes and status not in ["resolved", "closed"]:
                update_data["work_notes"] = resolution_notes
            
            # Update the incident
            response = self.session.put(
                f"{self.config.api_url}/api/now/table/incident/{incident_sys_id}",
                json=update_data
            )
            response.raise_for_status()
            
            self.logger.info(f"Updated ServiceNow incident {ticket_id} status to {status}")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to update ServiceNow incident {ticket_id}: {e}")
            return False
    
    def get_ticket(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        """Get incident details from ServiceNow."""
        try:
            # Search by incident number
            response = self.session.get(
                f"{self.config.api_url}/api/now/table/incident",
                params={
                    "sysparm_query": f"number={ticket_id}",
                    "sysparm_fields": "sys_id,number,short_description,description,state,priority,urgency,impact,assigned_to.name,caller_id.name,sys_created_on,sys_updated_on,resolved_at,close_notes,work_notes"
                }
            )
            response.raise_for_status()
            
            incidents = response.json()["result"]
            
            if not incidents:
                return None
            
            incident = incidents[0]
            
            # Map ServiceNow state to our status
            state_mapping = {
                "1": "open",           # New
                "2": "in_progress",    # In Progress
                "3": "in_progress",    # On Hold
                "6": "resolved",       # Resolved
                "7": "closed",         # Closed
                "8": "wont_fix"        # Canceled
            }
            
            status = state_mapping.get(incident.get("state", "1"), "open")
            
            return {
                "id": incident["number"],
                "sys_id": incident["sys_id"],
                "title": incident["short_description"],
                "description": incident.get("description", ""),
                "status": status,
                "priority": self._map_snow_priority(incident.get("priority", "3")),
                "assignee": incident.get("assigned_to.name", ""),
                "reporter": incident.get("caller_id.name", ""),
                "created_at": incident["sys_created_on"],
                "updated_at": incident["sys_updated_on"],
                "resolved_at": incident.get("resolved_at"),
                "resolution_notes": incident.get("close_notes", ""),
                "work_notes": incident.get("work_notes", ""),
                "url": f"{self.config.api_url}/nav_to.do?uri=incident.do?sys_id={incident['sys_id']}"
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get ServiceNow incident {ticket_id}: {e}")
            return None
    
    def search_tickets(self, query: str = "", assigned_to: str = "", state: str = "") -> List[Dict[str, Any]]:
        """Search for incidents in ServiceNow."""
        try:
            # Build query parameters
            query_parts = []
            
            if query:
                query_parts.append(f"short_descriptionLIKE{query}^ORdescriptionLIKE{query}")
            
            if assigned_to:
                user_sys_id = self._find_user_sys_id(assigned_to)
                if user_sys_id:
                    query_parts.append(f"assigned_to={user_sys_id}")
            
            if state:
                state_mapping = {
                    "open": "1",
                    "in_progress": "2",
                    "resolved": "6",
                    "closed": "7"
                }
                snow_state = state_mapping.get(state)
                if snow_state:
                    query_parts.append(f"state={snow_state}")
            
            # Add security category filter
            query_parts.append("category=Security")
            
            sysparm_query = "^".join(query_parts) if query_parts else "category=Security"
            
            response = self.session.get(
                f"{self.config.api_url}/api/now/table/incident",
                params={
                    "sysparm_query": sysparm_query,
                    "sysparm_fields": "sys_id,number,short_description,state,priority,assigned_to.name,sys_created_on,sys_updated_on",
                    "sysparm_limit": "50"
                }
            )
            response.raise_for_status()
            
            incidents = response.json()["result"]
            tickets = []
            
            for incident in incidents:
                state_mapping = {
                    "1": "open", "2": "in_progress", "3": "in_progress",
                    "6": "resolved", "7": "closed", "8": "wont_fix"
                }
                
                status = state_mapping.get(incident.get("state", "1"), "open")
                
                tickets.append({
                    "id": incident["number"],
                    "sys_id": incident["sys_id"],
                    "title": incident["short_description"],
                    "status": status,
                    "priority": self._map_snow_priority(incident.get("priority", "3")),
                    "assignee": incident.get("assigned_to.name", ""),
                    "created_at": incident["sys_created_on"],
                    "updated_at": incident["sys_updated_on"],
                    "url": f"{self.config.api_url}/nav_to.do?uri=incident.do?sys_id={incident['sys_id']}"
                })
            
            return tickets
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to search ServiceNow incidents: {e}")
            return []
    
    def add_comment(self, ticket_id: str, comment: str) -> bool:
        """Add work notes to a ServiceNow incident."""
        try:
            incident_sys_id = self._find_incident_sys_id(ticket_id)
            if not incident_sys_id:
                return False
            
            update_data = {
                "work_notes": comment
            }
            
            response = self.session.put(
                f"{self.config.api_url}/api/now/table/incident/{incident_sys_id}",
                json=update_data
            )
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to add comment to ServiceNow incident {ticket_id}: {e}")
            return False
    
    def _find_incident_sys_id(self, incident_number: str) -> Optional[str]:
        """Find incident sys_id by incident number."""
        try:
            response = self.session.get(
                f"{self.config.api_url}/api/now/table/incident",
                params={
                    "sysparm_query": f"number={incident_number}",
                    "sysparm_fields": "sys_id"
                }
            )
            response.raise_for_status()
            
            incidents = response.json()["result"]
            
            if incidents:
                return incidents[0]["sys_id"]
            
            return None
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to find ServiceNow incident {incident_number}: {e}")
            return None
    
    def _find_user_sys_id(self, identifier: str) -> Optional[str]:
        """Find user sys_id by username or email."""
        try:
            # Try username first
            response = self.session.get(
                f"{self.config.api_url}/api/now/table/sys_user",
                params={
                    "sysparm_query": f"user_name={identifier}^ORemail={identifier}",
                    "sysparm_fields": "sys_id"
                }
            )
            response.raise_for_status()
            
            users = response.json()["result"]
            
            if users:
                return users[0]["sys_id"]
            
            return None
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to find ServiceNow user {identifier}: {e}")
            return None
    
    def _map_priority(self, priority: str) -> str:
        """Map generic priority to ServiceNow priority."""
        priority_mapping = {
            "critical": "1",  # Critical
            "high": "2",      # High
            "medium": "3",    # Moderate
            "low": "4"        # Low
        }
        
        return priority_mapping.get(priority.lower(), "3")
    
    def _map_priority_to_urgency(self, priority: str) -> str:
        """Map priority to ServiceNow urgency."""
        urgency_mapping = {
            "critical": "1",  # High
            "high": "2",      # Medium
            "medium": "3",    # Low
            "low": "3"        # Low
        }
        
        return urgency_mapping.get(priority.lower(), "3")
    
    def _map_priority_to_impact(self, priority: str) -> str:
        """Map priority to ServiceNow impact."""
        impact_mapping = {
            "critical": "1",  # High
            "high": "2",      # Medium
            "medium": "3",    # Low
            "low": "3"        # Low
        }
        
        return impact_mapping.get(priority.lower(), "3")
    
    def _map_snow_priority(self, snow_priority: str) -> str:
        """Map ServiceNow priority to generic priority."""
        priority_mapping = {
            "1": "critical",
            "2": "high",
            "3": "medium",
            "4": "low"
        }
        
        return priority_mapping.get(snow_priority, "medium")
    
    def create_security_incident_template(self) -> Optional[str]:
        """Create a template for security incidents."""
        try:
            template_data = {
                "name": "Security Incident Template",
                "table": "incident",
                "template": json.dumps({
                    "category": "Security",
                    "subcategory": "Security Incident",
                    "priority": "2",
                    "urgency": "2",
                    "impact": "2",
                    "short_description": "Security Issue: [SEVERITY] [DESCRIPTION]",
                    "description": "Automated security incident created by Compliance Sentinel\\n\\nDetails:\\n- File: [FILE_PATH]\\n- Line: [LINE_NUMBER]\\n- Rule: [RULE_ID]\\n- Confidence: [CONFIDENCE]\\n\\nRemediation:\\n[REMEDIATION_SUGGESTIONS]"
                })
            }
            
            response = self.session.post(
                f"{self.config.api_url}/api/now/table/sys_template",
                json=template_data
            )
            response.raise_for_status()
            
            template = response.json()["result"]
            return template["sys_id"]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create ServiceNow template: {e}")
            return None
    
    def get_assignment_groups(self) -> List[Dict[str, Any]]:
        """Get available assignment groups."""
        try:
            response = self.session.get(
                f"{self.config.api_url}/api/now/table/sys_user_group",
                params={
                    "sysparm_query": "active=true",
                    "sysparm_fields": "sys_id,name,description"
                }
            )
            response.raise_for_status()
            
            groups = response.json()["result"]
            return [
                {
                    "id": group["sys_id"],
                    "name": group["name"],
                    "description": group.get("description", "")
                }
                for group in groups
            ]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get ServiceNow assignment groups: {e}")
            return []
    
    def bulk_update_incidents(self, incident_ids: List[str], updates: Dict[str, Any]) -> Dict[str, bool]:
        """Bulk update multiple incidents."""
        results = {}
        
        for incident_id in incident_ids:
            try:
                incident_sys_id = self._find_incident_sys_id(incident_id)
                if not incident_sys_id:
                    results[incident_id] = False
                    continue
                
                response = self.session.put(
                    f"{self.config.api_url}/api/now/table/incident/{incident_sys_id}",
                    json=updates
                )
                response.raise_for_status()
                results[incident_id] = True
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Failed to update ServiceNow incident {incident_id}: {e}")
                results[incident_id] = False
        
        return results