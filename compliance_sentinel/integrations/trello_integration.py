"""Trello integration for security board management."""

import requests
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from .ticket_manager import TicketConfig


logger = logging.getLogger(__name__)


class TrelloIntegration:
    """Trello integration for security board management."""
    
    def __init__(self, config: TicketConfig):
        """Initialize Trello integration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Validate configuration
        if not self.config.api_token or not self.config.api_url:
            raise ValueError("Trello API key and token are required")
        
        # Set up authentication parameters
        self.auth_params = {
            'key': self.config.api_url,  # API key stored in api_url field
            'token': self.config.api_token
        }
        
        # Validate connection
        self._validate_connection()
        
        # Get or create lists for different statuses
        self._setup_board_lists()
    
    def _validate_connection(self):
        """Validate Trello connection and get user info."""
        try:
            response = self.session.get(
                "https://api.trello.com/1/members/me",
                params=self.auth_params
            )
            response.raise_for_status()
            
            user_info = response.json()
            self.logger.info(f"Connected to Trello as {user_info.get('fullName', 'Unknown')}")
            
            # Validate board access if board_id is provided
            if self.config.board_id:
                self._validate_board()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to connect to Trello: {e}")
            raise
    
    def _validate_board(self):
        """Validate board access."""
        try:
            response = self.session.get(
                f"https://api.trello.com/1/boards/{self.config.board_id}",
                params=self.auth_params
            )
            response.raise_for_status()
            
            board_info = response.json()
            self.logger.info(f"Using Trello board: {board_info.get('name', 'Unknown')}")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to access Trello board {self.config.board_id}: {e}")
            raise
    
    def _setup_board_lists(self):
        """Set up or get board lists for different ticket statuses."""
        try:
            # Get existing lists
            response = self.session.get(
                f"https://api.trello.com/1/boards/{self.config.board_id}/lists",
                params=self.auth_params
            )
            response.raise_for_status()
            
            lists = response.json()
            
            # Map list names to IDs
            self.list_mapping = {}
            for list_item in lists:
                list_name = list_item['name'].lower()
                if 'open' in list_name or 'to do' in list_name or 'backlog' in list_name:
                    self.list_mapping['open'] = list_item['id']
                elif 'progress' in list_name or 'doing' in list_name:
                    self.list_mapping['in_progress'] = list_item['id']
                elif 'review' in list_name or 'testing' in list_name:
                    self.list_mapping['review'] = list_item['id']
                elif 'done' in list_name or 'resolved' in list_name or 'closed' in list_name:
                    self.list_mapping['resolved'] = list_item['id']
            
            # Create missing lists if needed
            required_lists = ['open', 'in_progress', 'resolved']
            for status in required_lists:
                if status not in self.list_mapping:
                    list_id = self._create_list(status.replace('_', ' ').title())
                    if list_id:
                        self.list_mapping[status] = list_id
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to setup Trello board lists: {e}")
            # Use first list as fallback
            self.list_mapping = {'open': lists[0]['id'] if lists else None}
    
    def _create_list(self, name: str) -> Optional[str]:
        """Create a new list on the board."""
        try:
            list_data = {
                'name': name,
                'idBoard': self.config.board_id,
                **self.auth_params
            }
            
            response = self.session.post(
                "https://api.trello.com/1/lists",
                params=list_data
            )
            response.raise_for_status()
            
            new_list = response.json()
            return new_list['id']
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create Trello list '{name}': {e}")
            return None
    
    def create_ticket(self, 
                     title: str,
                     description: str,
                     priority: str = "Medium",
                     assignee: str = "",
                     labels: List[str] = None,
                     due_date: datetime = None,
                     custom_fields: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Create a new Trello card."""
        
        try:
            # Get the list ID for open tickets
            list_id = self.list_mapping.get('open')
            if not list_id:
                self.logger.error("No 'open' list found on Trello board")
                return None
            
            # Prepare card data
            card_data = {
                'name': title,
                'desc': description,
                'idList': list_id,
                **self.auth_params
            }
            
            # Add due date if specified
            if due_date:
                card_data['due'] = due_date.isoformat()
            
            # Create the card
            response = self.session.post(
                "https://api.trello.com/1/cards",
                params=card_data
            )
            response.raise_for_status()
            
            created_card = response.json()
            
            # Add labels if specified
            if labels:
                self._add_labels_to_card(created_card['id'], labels)
            
            # Add priority label
            if priority and priority.lower() != "medium":
                self._add_labels_to_card(created_card['id'], [f"priority-{priority.lower()}"])
            
            # Add member if assignee specified
            if assignee:
                self._assign_member_to_card(created_card['id'], assignee)
            
            # Return card information
            return {
                "id": created_card['id'],
                "url": created_card['url'],
                "shortUrl": created_card['shortUrl']
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create Trello card: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response: {e.response.text}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error creating Trello card: {e}")
            return None
    
    def update_ticket_status(self, card_id: str, status: str, resolution_notes: str = "") -> bool:
        """Update card status by moving to appropriate list."""
        try:
            # Map status to list
            status_mapping = {
                'open': 'open',
                'in_progress': 'in_progress',
                'resolved': 'resolved',
                'closed': 'resolved'
            }
            
            target_status = status_mapping.get(status, 'open')
            target_list_id = self.list_mapping.get(target_status)
            
            if not target_list_id:
                self.logger.error(f"No list found for status '{status}'")
                return False
            
            # Move card to appropriate list
            update_data = {
                'idList': target_list_id,
                **self.auth_params
            }
            
            response = self.session.put(
                f"https://api.trello.com/1/cards/{card_id}",
                params=update_data
            )
            response.raise_for_status()
            
            # Add resolution notes as comment if provided
            if resolution_notes:
                self.add_comment(card_id, resolution_notes)
            
            self.logger.info(f"Updated Trello card {card_id} status to {status}")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to update Trello card {card_id}: {e}")
            return False
    
    def get_ticket(self, card_id: str) -> Optional[Dict[str, Any]]:
        """Get card details from Trello."""
        try:
            response = self.session.get(
                f"https://api.trello.com/1/cards/{card_id}",
                params={
                    'fields': 'name,desc,due,dateLastActivity,url,shortUrl,idList,labels,members',
                    **self.auth_params
                }
            )
            response.raise_for_status()
            
            card = response.json()
            
            # Determine status based on list
            status = 'open'  # default
            for status_name, list_id in self.list_mapping.items():
                if card['idList'] == list_id:
                    status = status_name
                    break
            
            # Extract priority from labels
            priority = 'medium'
            for label in card.get('labels', []):
                if label['name'].startswith('priority-'):
                    priority = label['name'].replace('priority-', '')
                    break
            
            return {
                "id": card['id'],
                "title": card['name'],
                "description": card.get('desc', ''),
                "status": status,
                "priority": priority,
                "assignee": card['members'][0]['fullName'] if card.get('members') else '',
                "due_date": card.get('due'),
                "updated_at": card.get('dateLastActivity'),
                "labels": [label['name'] for label in card.get('labels', [])],
                "url": card['url']
            }
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Trello card {card_id}: {e}")
            return None
    
    def search_tickets(self, query: str = "", list_name: str = "") -> List[Dict[str, Any]]:
        """Search for cards on the board."""
        try:
            # Get all cards from the board
            params = {
                'fields': 'name,desc,due,dateLastActivity,url,idList,labels,members',
                **self.auth_params
            }
            
            response = self.session.get(
                f"https://api.trello.com/1/boards/{self.config.board_id}/cards",
                params=params
            )
            response.raise_for_status()
            
            cards = response.json()
            results = []
            
            for card in cards:
                # Filter by query if provided
                if query and query.lower() not in card['name'].lower():
                    continue
                
                # Filter by list if provided
                if list_name:
                    target_list_id = self.list_mapping.get(list_name.lower())
                    if target_list_id and card['idList'] != target_list_id:
                        continue
                
                # Determine status
                status = 'open'
                for status_name, list_id in self.list_mapping.items():
                    if card['idList'] == list_id:
                        status = status_name
                        break
                
                results.append({
                    "id": card['id'],
                    "title": card['name'],
                    "status": status,
                    "assignee": card['members'][0]['fullName'] if card.get('members') else '',
                    "due_date": card.get('due'),
                    "updated_at": card.get('dateLastActivity'),
                    "labels": [label['name'] for label in card.get('labels', [])],
                    "url": card['url']
                })
            
            return results
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to search Trello cards: {e}")
            return []
    
    def add_comment(self, card_id: str, comment: str) -> bool:
        """Add a comment to a Trello card."""
        try:
            comment_data = {
                'text': comment,
                **self.auth_params
            }
            
            response = self.session.post(
                f"https://api.trello.com/1/cards/{card_id}/actions/comments",
                params=comment_data
            )
            response.raise_for_status()
            
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to add comment to Trello card {card_id}: {e}")
            return False
    
    def _add_labels_to_card(self, card_id: str, label_names: List[str]):
        """Add labels to a card."""
        try:
            # Get existing labels on the board
            response = self.session.get(
                f"https://api.trello.com/1/boards/{self.config.board_id}/labels",
                params=self.auth_params
            )
            response.raise_for_status()
            
            board_labels = response.json()
            
            for label_name in label_names:
                # Find existing label or create new one
                label_id = None
                
                for label in board_labels:
                    if label['name'].lower() == label_name.lower():
                        label_id = label['id']
                        break
                
                # Create label if it doesn't exist
                if not label_id:
                    label_id = self._create_label(label_name)
                
                # Add label to card
                if label_id:
                    self.session.post(
                        f"https://api.trello.com/1/cards/{card_id}/idLabels",
                        params={'value': label_id, **self.auth_params}
                    )
                    
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to add labels to Trello card {card_id}: {e}")
    
    def _create_label(self, name: str, color: str = "red") -> Optional[str]:
        """Create a new label on the board."""
        try:
            label_data = {
                'name': name,
                'color': color,
                'idBoard': self.config.board_id,
                **self.auth_params
            }
            
            response = self.session.post(
                "https://api.trello.com/1/labels",
                params=label_data
            )
            response.raise_for_status()
            
            new_label = response.json()
            return new_label['id']
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to create Trello label '{name}': {e}")
            return None
    
    def _assign_member_to_card(self, card_id: str, member_identifier: str):
        """Assign a member to a card."""
        try:
            # Try to find member by username or email
            member_id = self._find_member_id(member_identifier)
            
            if member_id:
                response = self.session.post(
                    f"https://api.trello.com/1/cards/{card_id}/idMembers",
                    params={'value': member_id, **self.auth_params}
                )
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to assign member to Trello card {card_id}: {e}")
    
    def _find_member_id(self, identifier: str) -> Optional[str]:
        """Find member ID by username or email."""
        try:
            # Get board members
            response = self.session.get(
                f"https://api.trello.com/1/boards/{self.config.board_id}/members",
                params=self.auth_params
            )
            response.raise_for_status()
            
            members = response.json()
            
            for member in members:
                if (member.get('username', '').lower() == identifier.lower() or
                    member.get('email', '').lower() == identifier.lower() or
                    member.get('fullName', '').lower() == identifier.lower()):
                    return member['id']
            
            return None
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to find Trello member '{identifier}': {e}")
            return None
    
    def get_board_info(self) -> Optional[Dict[str, Any]]:
        """Get board information."""
        try:
            response = self.session.get(
                f"https://api.trello.com/1/boards/{self.config.board_id}",
                params={
                    'fields': 'name,desc,url,dateLastActivity',
                    **self.auth_params
                }
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Trello board info: {e}")
            return None
    
    def get_board_members(self) -> List[Dict[str, Any]]:
        """Get board members for task assignment."""
        try:
            response = self.session.get(
                f"https://api.trello.com/1/boards/{self.config.board_id}/members",
                params={
                    'fields': 'username,fullName,email',
                    **self.auth_params
                }
            )
            response.raise_for_status()
            
            members = response.json()
            return [
                {
                    "id": member['id'],
                    "username": member.get('username', ''),
                    "name": member.get('fullName', ''),
                    "email": member.get('email', '')
                }
                for member in members
            ]
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get Trello board members: {e}")
            return []