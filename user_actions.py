import boto3
import json
from datetime import datetime, timedelta

# Define creation event patterns
# These are AWS API calls that create resources
CREATION_EVENT_PATTERNS = [
    'Create',      # CreateVpc, CreateSubnet, CreateSecurityGroup, etc.
    'Run',         # RunInstances (EC2)
    'Launch',      # LaunchTemplate, etc.
    'Allocate',    # AllocateAddress (Elastic IP)
    'Associate',   # AssociateRouteTable, etc. (some create associations)
    'Attach',      # AttachInternetGateway, etc.
    'Register',    # RegisterImage, etc.
    'Put',         # PutBucketPolicy, PutObject (S3)
]

# Deletion order: resources must be deleted in reverse dependency order
# Lower number = delete first, higher number = delete last
RESOURCE_DELETION_ORDER = {
    'RunInstances': 1,              # EC2 instances first
    'CreateNetworkInterface': 2,    # ENIs
    'CreateNatGateway': 3,          # NAT Gateways
    'AllocateAddress': 4,           # Elastic IPs
    'CreateRouteTable': 5,          # Route tables
    'CreateSubnet': 6,              # Subnets
    'CreateInternetGateway': 7,     # Internet Gateways
    'CreateSecurityGroup': 8,       # Security Groups
    'CreateVpc': 9,                 # VPCs last
}

def extract_resource_ids(event_name, cloud_trail_event):
    """
    Extract resource IDs and types from CloudTrail event response.
    
    Args:
        event_name: The AWS API event name
        cloud_trail_event: Parsed CloudTrailEvent JSON
    
    Returns:
        List of dicts with 'id', 'type', and 'name' keys
    """
    response_elements = cloud_trail_event.get('responseElements', {})
    request_parameters = cloud_trail_event.get('requestParameters', {})
    resources = []
    
    # Extract based on event type
    if event_name == 'CreateVpc':
        vpc = response_elements.get('vpc', {})
        if vpc:
            resources.append({
                'id': vpc.get('vpcId'),
                'type': 'VPC',
                'name': vpc.get('vpcId'),
                'cidr': vpc.get('cidrBlock')
            })
    
    elif event_name == 'CreateSubnet':
        subnet = response_elements.get('subnet', {})
        if subnet:
            resources.append({
                'id': subnet.get('subnetId'),
                'type': 'Subnet',
                'name': subnet.get('subnetId'),
                'vpc_id': subnet.get('vpcId'),
                'cidr': subnet.get('cidrBlock'),
                'az': subnet.get('availabilityZone')
            })
    
    elif event_name == 'CreateSecurityGroup':
        resources.append({
            'id': response_elements.get('groupId'),
            'type': 'SecurityGroup',
            'name': request_parameters.get('groupName'),
            'vpc_id': request_parameters.get('vpcId')
        })
    
    elif event_name == 'CreateInternetGateway':
        igw = response_elements.get('internetGateway', {})
        if igw:
            resources.append({
                'id': igw.get('internetGatewayId'),
                'type': 'InternetGateway',
                'name': igw.get('internetGatewayId')
            })
    
    elif event_name == 'CreateRouteTable':
        rt = response_elements.get('routeTable', {})
        if rt:
            resources.append({
                'id': rt.get('routeTableId'),
                'type': 'RouteTable',
                'name': rt.get('routeTableId'),
                'vpc_id': rt.get('vpcId')
            })
    
    elif event_name == 'CreateNatGateway':
        nat = response_elements.get('natGateway', {})
        if nat:
            resources.append({
                'id': nat.get('natGatewayId'),
                'type': 'NatGateway',
                'name': nat.get('natGatewayId'),
                'subnet_id': nat.get('subnetId')
            })
    
    elif event_name == 'AllocateAddress':
        resources.append({
            'id': response_elements.get('allocationId'),
            'type': 'ElasticIP',
            'name': response_elements.get('publicIp'),
            'public_ip': response_elements.get('publicIp')
        })
    
    elif event_name == 'RunInstances':
        instances = response_elements.get('instancesSet', {}).get('items', [])
        for instance in instances:
            resources.append({
                'id': instance.get('instanceId'),
                'type': 'EC2Instance',
                'name': instance.get('instanceId'),
                'instance_type': instance.get('instanceType'),
                'subnet_id': instance.get('subnetId'),
                'vpc_id': instance.get('vpcId')
            })
    
    elif event_name == 'CreateNetworkInterface':
        eni = response_elements.get('networkInterface', {})
        if eni:
            resources.append({
                'id': eni.get('networkInterfaceId'),
                'type': 'NetworkInterface',
                'name': eni.get('networkInterfaceId'),
                'subnet_id': eni.get('subnetId'),
                'vpc_id': eni.get('vpcId')
            })
    
    # Add more resource types as needed
    
    return resources

def is_creation_event(event_name, patterns=None):
    """
    Check if an event name represents a creation action.
    
    Args:
        event_name: The AWS API event name (e.g., 'CreateVpc')
        patterns: List of prefixes to match (default: CREATION_EVENT_PATTERNS)
    
    Returns:
        True if the event creates a resource
    """
    if patterns is None:
        patterns = CREATION_EVENT_PATTERNS
    
    return any(event_name.startswith(pattern) for pattern in patterns)

def get_user_vpc_creations(identifier, days_back=90, search_by_username=True, 
                           creation_patterns=None, show_stats=True):
    """
    Get resource creation events for a user with full deletion information.
    
    Args:
        identifier: The username, principalId, or session name to search for
                   If principalId format (contains ':'), will extract session name
        days_back: Number of days to look back (max 90 for CloudTrail Event History)
        search_by_username: If True, use Username attribute for API-level filtering (recommended);
                           if False, fetch all events and filter client-side
        creation_patterns: List of event name prefixes to consider as creation events
                          (default: CREATION_EVENT_PATTERNS)
        show_stats: If True, display statistics about filtered events
    
    Returns:
        List of creation events with resource IDs, types, and deletion order
    """
    client = boto3.client('cloudtrail')
    paginator = client.get_paginator('lookup_events')
    
    # Define time range (CloudTrail Event History is limited to 90 days)
    start_time = datetime.now() - timedelta(days=days_back)
    
    created_resources = []
    total_events_scanned = 0
    
    # Extract session name if identifier is a full principalId
    search_value = identifier
    if ':' in identifier:
        # This is a principalId like 'AROAKE4VKVPOBNHFXILAU:1034028644'
        # Extract the session name (part after colon) to use as Username
        search_value = identifier.split(':', 1)[1]
        print(f"Extracted session name from principalId: {search_value}")
    
    if search_by_username:
        # Use Username attribute for API-level filtering (MUCH faster!)
        # The AWS Console uses this approach - the session name matches the Username field
        print(f"Searching events by Username: {search_value}")
        print("Using API-level filtering (efficient)...")
        
        page_iterator = paginator.paginate(
            LookupAttributes=[
                {
                    'AttributeKey': 'Username',
                    'AttributeValue': search_value
                }
            ],
            StartTime=start_time
        )
        
        for page in page_iterator:
            for event in page.get('Events', []):
                total_events_scanned += 1
                event_name = event.get('EventName', '')
                
                # Filter for creation events EARLY (before parsing full event)
                if not is_creation_event(event_name, creation_patterns):
                    continue
                
                # Parse CloudTrailEvent to get full details
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                user_identity = cloud_trail_event.get('userIdentity', {})
                principal_id = user_identity.get('principalId', '')
                
                # Extract resource IDs and details from response
                resource_details = extract_resource_ids(event_name, cloud_trail_event)
                
                # Get region from event
                region = cloud_trail_event.get('awsRegion', 'unknown')
                
                # Extract session name for display
                session_name = principal_id.split(':', 1)[1] if ':' in principal_id else 'N/A'
                role_id = principal_id.split(':', 1)[0] if ':' in principal_id else principal_id
                
                # Get deletion order priority
                deletion_order = RESOURCE_DELETION_ORDER.get(event_name, 99)
                
                created_resources.append({
                    'EventTime': event.get('EventTime').strftime('%Y-%m-%d %H:%M:%S'),
                    'EventTimestamp': event.get('EventTime'),
                    'Action': event_name,
                    'Region': region,
                    'ResourceDetails': resource_details,
                    'DeletionOrder': deletion_order,
                    'PrincipalId': principal_id,
                    'RoleId': role_id,
                    'SessionName': session_name,
                    'Username': event.get('Username', ''),
                    'EventId': event.get('EventId', ''),
                    'FullEvent': cloud_trail_event  # Keep full event for debugging
                })
    else:
        # Fallback: fetch all events and filter client-side (slower)
        print(f"Scanning all events and filtering for: {search_value}")
        print("Note: This may take longer as we need to parse all events...")
        
        page_iterator = paginator.paginate(
            StartTime=start_time
        )
        
        for page in page_iterator:
            for event in page.get('Events', []):
                total_events_scanned += 1
                event_name = event.get('EventName', '')
                
                # Parse the CloudTrailEvent JSON to access userIdentity
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                user_identity = cloud_trail_event.get('userIdentity', {})
                
                # Extract principalId and username for comparison
                principal_id = user_identity.get('principalId', '')
                username = event.get('Username', '')
                
                # Check if this event matches our identifier
                session_name = principal_id.split(':', 1)[1] if ':' in principal_id else ''
                matches = (principal_id == identifier or 
                          session_name == search_value or 
                          username == search_value)
                
                if not matches:
                    continue
                
                # Filter for creation events
                if not is_creation_event(event_name, creation_patterns):
                    continue
                
                # Extract resource IDs and details
                resource_details = extract_resource_ids(event_name, cloud_trail_event)
                
                # Get region from event
                region = cloud_trail_event.get('awsRegion', 'unknown')
                
                # Get deletion order priority
                deletion_order = RESOURCE_DELETION_ORDER.get(event_name, 99)
                
                role_id = principal_id.split(':', 1)[0] if ':' in principal_id else principal_id
                
                created_resources.append({
                    'EventTime': event.get('EventTime').strftime('%Y-%m-%d %H:%M:%S'),
                    'EventTimestamp': event.get('EventTime'),
                    'Action': event_name,
                    'Region': region,
                    'ResourceDetails': resource_details,
                    'DeletionOrder': deletion_order,
                    'PrincipalId': principal_id,
                    'RoleId': role_id,
                    'SessionName': session_name if session_name else 'N/A',
                    'Username': username,
                    'EventId': event.get('EventId', ''),
                    'FullEvent': cloud_trail_event
                })
    
    if show_stats:
        print(f"\nScanned {total_events_scanned} total events")
        print(f"Found {len(created_resources)} creation events")
        if total_events_scanned > 0:
            percentage = (len(created_resources) / total_events_scanned) * 100
            print(f"Creation events: {percentage:.1f}% of total")

    return created_resources

def generate_deletion_plan(resources):
    """
    Generate a deletion plan with resources sorted by dependency order.
    
    Args:
        resources: List of resource creation events
    
    Returns:
        Dict with deletion plan organized by order and resource type
    """
    # Sort by deletion order (ascending) and then by timestamp (descending - newest first)
    sorted_resources = sorted(resources, 
                             key=lambda x: (x['DeletionOrder'], -x['EventTimestamp'].timestamp()))
    
    deletion_plan = {}
    for resource in sorted_resources:
        order = resource['DeletionOrder']
        if order not in deletion_plan:
            deletion_plan[order] = []
        deletion_plan[order].append(resource)
    
    return deletion_plan

def print_deletion_plan(deletion_plan):
    """
    Print a formatted deletion plan.
    """
    print("\n" + "="*100)
    print("DELETION PLAN (Execute in this order)")
    print("="*100)
    
    for order in sorted(deletion_plan.keys()):
        resources = deletion_plan[order]
        print(f"\n--- Step {order}: Delete {len(resources)} resource(s) ---")
        
        for resource in resources:
            print(f"\n  Event: {resource['Action']}")
            print(f"  Time: {resource['EventTime']}")
            print(f"  Region: {resource['Region']}")
            print(f"  Event ID: {resource['EventId']}")
            
            if resource['ResourceDetails']:
                for detail in resource['ResourceDetails']:
                    print(f"  Resource Type: {detail['type']}")
                    print(f"  Resource ID: {detail['id']}")
                    if 'name' in detail and detail['name'] != detail['id']:
                        print(f"  Name: {detail['name']}")
                    # Print additional details
                    for key, value in detail.items():
                        if key not in ['type', 'id', 'name']:
                            print(f"  {key}: {value}")
            else:
                print(f"  WARNING: No resource details extracted - manual review needed")

def export_to_json(resources, filename='resources_to_delete.json'):
    """
    Export resources to JSON file for programmatic deletion.
    """
    # Remove FullEvent to reduce file size
    export_data = []
    for r in resources:
        export_item = {k: v for k, v in r.items() if k != 'FullEvent'}
        # Convert datetime to string
        if 'EventTimestamp' in export_item:
            export_item['EventTimestamp'] = export_item['EventTimestamp'].isoformat()
        export_data.append(export_item)
    
    with open(filename, 'w') as f:
        json.dump(export_data, f, indent=2, default=str)
    
    print(f"\n✅ Exported {len(export_data)} resources to {filename}")

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

# Auto-detect identifier type
identifier_type = detect_identifier_type(USER_TO_CHECK)

print(f"Detected identifier type: {identifier_type}")
if ':' in USER_TO_CHECK:
    role_id, session_name = USER_TO_CHECK.split(':', 1)
    print(f"  Role ID: {role_id} (constant for role PROJADMIN)")
    print(f"  Session Name: {session_name} (unique user identifier)")
    print(f"\nSearching by Username='{session_name}' (same approach as AWS Console)")

print(f"\nFiltering for creation events matching: {', '.join(CREATION_EVENT_PATTERNS)}")

# Get all creation events
results = get_user_vpc_creations(USER_TO_CHECK, search_by_username=True)

if results:
    # Generate deletion plan
    deletion_plan = generate_deletion_plan(results)
    print_deletion_plan(deletion_plan)
    
    # Export to JSON
    export_to_json(results)
    
    print(f"\n{'='*100}")
    print(f"Total creation events found: {len(results)}")
    print(f"Filtered by Username='{extract_session_name(USER_TO_CHECK)}'")
    print(f"{'='*100}")
    
    print("\n⚠️  IMPORTANT NOTES:")
    print("1. Review the deletion plan carefully before executing")
    print("2. Some resources may have dependencies not captured in CloudTrail")
    print("3. Resources created >90 days ago won't appear in CloudTrail Event History")
    print("4. Consider using AWS Config or Resource Groups for complete inventory")
    print("5. Test deletion in a non-production environment first")
else:
    print("\nNo creation events found in the last 90 days.")
