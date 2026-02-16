import boto3
import json
from datetime import datetime, timedelta

def get_user_vpc_creations(identifier, days_back=90, search_by_principal_id=True, match_session_name_only=False):
    """
    Get VPC creation events for a user.
    
    Args:
        identifier: The username, principalId, or session name to search for
        days_back: Number of days to look back (max 90 for CloudTrail Event History)
        search_by_principal_id: If True, search by userIdentity.principalId; 
                                if False, use Username attribute
        match_session_name_only: If True, match only the session name part (after colon) 
                                 of principalId for assumed roles
    
    Returns:
        List of creation events
    """
    client = boto3.client('cloudtrail')
    paginator = client.get_paginator('lookup_events')
    
    # Define time range (CloudTrail Event History is limited to 90 days)
    start_time = datetime.now() - timedelta(days=days_back)
    
    created_resources = []
    
    if search_by_principal_id:
        # When searching by principalId, we need to fetch all events and filter manually
        # since CloudTrail lookup_events doesn't support principalId as a LookupAttribute
        print(f"Scanning events for principalId: {identifier}...")
        if match_session_name_only:
            print(f"Note: Matching session name only (part after colon)")
        print("Note: This may take longer as we need to parse all events...")
        
        page_iterator = paginator.paginate(
            StartTime=start_time
        )
        
        for page in page_iterator:
            for event in page.get('Events', []):
                event_name = event.get('EventName', '')
                
                # Parse the CloudTrailEvent JSON to access userIdentity
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                user_identity = cloud_trail_event.get('userIdentity', {})
                
                # Extract principalId and username for comparison
                principal_id = user_identity.get('principalId', '')
                username = event.get('Username', '')
                
                # Check if this event matches our identifier
                matches = False
                if match_session_name_only and ':' in principal_id:
                    # Match only the session name part (after colon)
                    session_name = principal_id.split(':', 1)[1]
                    matches = (session_name == identifier or username == identifier)
                else:
                    # Match full principalId or username
                    matches = (principal_id == identifier or username == identifier)
                
                if not matches:
                    continue
                
                # Filter for 'Create' actions related to VPC components
                if event_name.startswith('Create') or event_name == 'RunInstances':
                    # Extract resource details
                    resources = event.get('Resources', [])
                    resource_names = [r.get('ResourceName') for r in resources]
                    
                    # Extract session name for display
                    session_name = principal_id.split(':', 1)[1] if ':' in principal_id else 'N/A'
                    role_id = principal_id.split(':', 1)[0] if ':' in principal_id else principal_id
                    
                    created_resources.append({
                        'EventTime': event.get('EventTime').strftime('%Y-%m-%d %H:%M:%S'),
                        'Action': event_name,
                        'Resources': resource_names,
                        'PrincipalId': principal_id,
                        'RoleId': role_id,
                        'SessionName': session_name,
                        'Username': username
                    })
    else:
        # Use the original method - filter by Username at API level
        print(f"Scanning events for username: {identifier}...")
        
        page_iterator = paginator.paginate(
            LookupAttributes=[
                {
                    'AttributeKey': 'Username',
                    'AttributeValue': identifier
                }
            ],
            StartTime=start_time
        )
        
        for page in page_iterator:
            for event in page.get('Events', []):
                event_name = event.get('EventName', '')
                
                # Filter for 'Create' actions related to VPC components
                if event_name.startswith('Create') or event_name == 'RunInstances':
                    # Parse CloudTrailEvent to get userIdentity info
                    cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                    user_identity = cloud_trail_event.get('userIdentity', {})
                    principal_id = user_identity.get('principalId', '')
                    
                    # Extract resource details
                    resources = event.get('Resources', [])
                    resource_names = [r.get('ResourceName') for r in resources]
                    
                    # Extract session name for display
                    session_name = principal_id.split(':', 1)[1] if ':' in principal_id else 'N/A'

if search_by_principal_id:
    # When searching by principalId, we need to fetch all events and filter manually
    # since CloudTrail lookup_events doesn't support principalId as a LookupAttribute
    #
    # Available LookupAttributes: AccessKeyId, EventId, EventName, EventSource,
    # ReadOnly, ResourceName, ResourceType, Username
    #
    # For better performance with principalId filtering, consider:
    # 1. Using CloudTrail Lake with SQL queries (supports all fields)
    # 2. Filtering by AccessKeyId if known (but keys rotate for assumed roles)
    # 3. Filtering by Username if it matches the session name
    print(f"Scanning events for principalId: {identifier}...")
    if match_session_name_only:
        print(f"Note: Matching session name only (part after colon)")
    print("Note: This may take longer as we need to parse all events...")
    print("      (CloudTrail API doesn't support principalId filtering)")
                    role_id = principal_id.split(':', 1)[0] if ':' in principal_id else principal_id
                    
                    created_resources.append({
                        'EventTime': event.get('EventTime').strftime('%Y-%m-%d %H:%M:%S'),
                        'Action': event_name,
                        'Resources': resource_names,
                        'PrincipalId': principal_id,
                        'RoleId': role_id,
                        'SessionName': session_name,
                        'Username': event.get('Username', '')
                    })

    return created_resources

def detect_identifier_type(identifier):
    """
    Detect if the identifier is likely a principalId or username.
    
    PrincipalId formats:
    - Assumed Role: AROXXXXXXXXXXXXX:sessionName (e.g., AROAKE4VKVPOBNHFXILAU:1034028644)
    - IAM User: AIDAXXXXXXXXXXXXX
    - Federated User: AROXXXXXXXXXXXXX:federatedUser
    
    The part before the colon (ARO...) is the Role's unique ID (constant for the role)
    The part after the colon is the RoleSessionName (unique per user/session)
    """
    # PrincipalIds for assumed roles contain a colon
    if ':' in identifier:
        return 'principalId'
    # PrincipalIds starting with ARO, AIDA, AGPA are IAM identifiers
    elif identifier.startswith(('ARO', 'AIDA', 'AGPA')):
        return 'principalId'
    else:
        return 'username'

def extract_session_name(principal_id):
    """
    Extract the session name (part after colon) from a principalId.
    
    Args:
        principal_id: Full principalId like 'AROAKE4VKVPOBNHFXILAU:1034028644'
    
    Returns:
        Session name (e.g., '1034028644') or the full principalId if no colon found
    """
    if ':' in principal_id:
        return principal_id.split(':', 1)[1]
    return principal_id

# Usage
USER_TO_CHECK = 'AROAKE4VKVPOBNHFXILAU:1034028644'  # Replace with the IAM username or principalId

# Auto-detect whether to search by principalId or username
identifier_type = detect_identifier_type(USER_TO_CHECK)
search_by_principal = (identifier_type == 'principalId')

print(f"Detected identifier type: {identifier_type}")
if ':' in USER_TO_CHECK:
    role_id, session_name = USER_TO_CHECK.split(':', 1)
    print(f"  Role ID: {role_id} (constant for role PROJADMIN)")
    print(f"  Session Name: {session_name} (unique user identifier)")

results = get_user_vpc_creations(USER_TO_CHECK, search_by_principal_id=search_by_principal)

if results:
    print(f"\n{'Date':<20} | {'Action':<25} | {'Session':<15} | {'Username':<20} | {'Resource ID'}")
    print("-" * 120)
    for r in results:
        resources_str = ', '.join(r['Resources']) if r['Resources'] else 'N/A'
        print(f"{r['EventTime']:<20} | {r['Action']:<25} | {r['SessionName']:<15} | {r['Username']:<20} | {resources_str}")
    
    print(f"\nTotal events found: {len(results)}")
    print(f"\nNote: All events are for principalId: {USER_TO_CHECK}")
else:
    print("No creation events found in the last 90 days.")
