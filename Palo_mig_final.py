import pandas as pd

# Load the CSV files, Change the names.
address_groups_df = pd.read_csv('pa_address_groups.csv')
name_to_ip_df = pd.read_csv('pa_objects_addresses.csv')
policies_df = pd.read_csv('pa_policies.csv')
services_df = pd.read_csv('pa_services.csv')

#When using Palo-Alto policies.csv, application-Defualt in the service column will map to '*', unless it matches a service in 'Services.csv' via tcp-<#> or Service-<name>. May fix it later...

# Function to resolve ports for a given service name
def resolve_service_ports(service_name):
    service_entries = service_name.lower().split(';')  # Split services by semicolons
    ports = []
    protocol = 'Any'  # Default protocol

    for entry in service_entries:
        entry = entry.strip()
        service_port = services_df.loc[services_df['Name'].str.lower() == entry]

        if not service_port.empty:
            port_value = service_port['Destination Port'].values[0]
            port_list = port_value.split(',')  # Split ports by commas
            for port in port_list:
                # Check if the port is a range
                if '-' in port:
                    ports.append(f"'{port}'")  # Quote the range in single quotes
                else:
                    ports.append(port)  # Add the port as is if it's not a range
        else:
            ports.append('*')  # Default to '*' if not found

    return ports, protocol  # Return ports as a list now

# Initialize the list for the PowerShell commands
powershell_commands = []

# Initialize the IP groups dictionary
azure_ip_groups = {}

# Initialize a dictionary to hold rule collections and their respective rules
rule_collections = {}

# Add input variable block at the top of the PowerShell script
powershell_commands.append("# Input Variables")
powershell_commands.append('$AzFwPolicyName = ""  # Variable for Azure Firewall Policy Name')
powershell_commands.append('$FWSkuTier = "Premium"  # Variable for Azure Firewall Policy Sku')
powershell_commands.append('$IPGroupRG = ""  # Variable for IPGroup Resource Group')
powershell_commands.append('$FWPolicyRG = ""  # Variable for Firewall Policy Resource Group ')
powershell_commands.append('$Region = ""  # Variable for Azure Region ')
powershell_commands.append('$NetworkRCGroupName = "" # Network Rule Collection Group Name')
powershell_commands.append("")  # Add an empty line for better readability

# Add input validation for critical variables in PowerShell script
powershell_commands.append("# Validate Input Variables")
powershell_commands.append("if (-not $AzFwPolicyName) { throw 'Firewall policy name cannot be empty.' }")
powershell_commands.append("if (-not $IPGroupRG) { throw 'Resource group name cannot be empty.' }")
powershell_commands.append("if (-not $FWPolicyRG) { throw 'Firewall Policy Resource group name cannot be empty.' }")
powershell_commands.append("if (-not $Region) { throw 'Region cannot be empty.' }")
powershell_commands.append("if (-not $NetworkRCGroupName) { throw 'Network Rule collection group Name cannot be empty.' }")
powershell_commands.append("")  # Add an empty line for better readability

# Create Azure IP Groups based on existing address groups
powershell_commands.append("$azureIpGroups = @{}")

# Create a set of existing address group names for quick lookup
existing_groups = set(address_groups_df['name'])

# Collect IP addresses for existing address groups, skipping FQDNs
for _, group in address_groups_df.iterrows():
    group_name = group['name']
    addresses = group['Addresses'].split(';')

    # Initialize a list to hold the resolved IP addresses
    ip_addresses = []

    # Collect IP addresses for this group
    for address in addresses:
        address = address.strip()  # Clean up whitespace
        ip_object = name_to_ip_df.loc[name_to_ip_df['Name'] == address]

        # Check if the IP object is not empty and its type is not "FQDN"
        if not ip_object.empty and ip_object['Type'].values[0] != 'FQDN':
            ip_address = ip_object['Address'].values[0]  # Get IP
            ip_addresses.append(ip_address)  # Add to list

    # Store the IP addresses for existing groups in the azure_ip_groups dictionary
    if ip_addresses:
        azure_ip_groups[group_name] = ip_addresses

# Collect IP addresses from pa_objects_addresses that are not in existing address groups, excluding FQDNs
non_member_addresses = name_to_ip_df[~name_to_ip_df['Name'].isin(existing_groups) & (name_to_ip_df['Type'] != 'FQDN')]

# Create Azure IP Groups for non-member addresses
for _, address_row in non_member_addresses.iterrows():
    address_name = address_row['Name']
    address_ip = address_row['Address']

    # Check if there's a dot in the name and handle truncating the part before the dot
    if '.' in address_name:
        group_name = address_name.split('.', 1)[0][:6].lower()  # Truncate to the first 6 characters before the dot
    else:
        group_name = address_name[:6].lower()  # If no dot, just take the first 6 characters

    # Append to the azure_ip_groups dictionary
    if address_ip:  # Only add if there is an IP
        if group_name not in azure_ip_groups:
            azure_ip_groups[group_name] = [address_ip]  # Start a new list
        else:
            azure_ip_groups[group_name].append(address_ip)  # Append IP to existing group

# Create Azure IP Groups for PowerShell and assign to variables
powershell_commands.append("# Create Azure IP Groups")
for group_name, ip_list in azure_ip_groups.items():
    ip_list_string = ','.join([f"'{ip}'" for ip in ip_list])  # Format IPs for PowerShell
    # Assign the IP group to a PowerShell variable
    powershell_commands.append(f"${group_name} = New-AzIpGroup -ResourceGroupName $IPGroupRG -Name '{group_name}' -IpAddress @({ip_list_string}) -Location $Region")

# Add a blank line for spacing before the next comment
powershell_commands.append("")

# Start creating the Azure Firewall Premium policy
powershell_commands.append(f"# Create Azure Firewall Premium Policy")
powershell_commands.append(f"$fwpol = New-AzFirewallPolicy -Name $AzFwPolicyName -ResourceGroupName $FWPolicyRG -Location $Region -SkuTier $FWSkuTier")

# Add a blank line for spacing before the next comment
powershell_commands.append("")

# Create the Rule Collection Group
powershell_commands.append(f"# Create Rule Collection Group")
powershell_commands.append(f"$NetworkRuleCollectionGroup = New-AzFirewallPolicyRuleCollectionGroup -Name $NetworkRCGroupName -Priority 200 -ResourceGroupName $FWPolicyRG -FirewallPolicyName $AzFwPolicyName")

# Initialize starting priority for rule collections
priority = 100  # Starting priority

# Function to resolve addresses (handles both IP groups and individual addresses)
import re

def resolve_address(address, is_source):
    resolved_ip_groups = []  # List to hold IP groups
    resolved_ips = []  # List to hold individual IP addresses
    added_items = set()  # To track added IP groups or addresses and avoid duplication

    # Regular expression to match IP addresses and ranges
    ip_range_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')  # Handles IP and CIDR ranges

    for addr in address.split(';'):
        addr = addr.strip()

        # Handle 'any' as a wildcard
        if addr.lower() == 'any':
            if '*' not in added_items:  # Ensure '*' is only added once
                resolved_ips.append("'*'")
                added_items.add('*')

        # Check if it's a valid IP address or range
        elif ip_range_regex.match(addr):
            if addr not in added_items:  # Ensure IP is only added once
                resolved_ips.append(f"'{addr}'")  # Directly add IP or range
                added_items.add(addr)

        # Check if the address is part of an IP group
        elif addr in azure_ip_groups:
            if addr not in added_items:  # Ensure group is only added once
                resolved_ip_groups.append(f"${addr.lower()}.Id")  # Use the IP group Id variable
                added_items.add(addr)

        # Try to resolve the address to an IP in name_to_ip_df
        else:
            ip_object = name_to_ip_df.loc[name_to_ip_df['Name'] == addr]
            if not ip_object.empty:
                ip_address = ip_object['Address'].values[0]

                # Check if this IP exists in any of the IP groups
                found_in_group = False
                for group_name, ips in azure_ip_groups.items():
                    if ip_address in ips:
                        if group_name not in added_items:  # Ensure group is only added once
                            resolved_ip_groups.append(f"${group_name.lower()}.Id")  # Use the IP group Id variable
                            added_items.add(group_name)
                        found_in_group = True
                        break

                # If the IP is not part of a group, use the IP directly
                if not found_in_group and ip_address not in added_items:
                    resolved_ips.append(f"'{ip_address}'")
                    added_items.add(ip_address)

    # Build the output, omitting empty entries
    result = []

    if len(resolved_ip_groups) > 1:
        result.append(f"-{'SourceIPGroup' if is_source else 'DestinationIPGroup'} @({','.join(resolved_ip_groups)})")
    elif len(resolved_ip_groups) == 1:
        result.append(f"-{'SourceIPGroup' if is_source else 'DestinationIPGroup'} {resolved_ip_groups[0]}")

    if len(resolved_ips) > 1:
        result.append(f"-{'SourceAddress' if is_source else 'DestinationAddress'} @({','.join(resolved_ips)})")
    elif len(resolved_ips) == 1:
        result.append(f"-{'SourceAddress' if is_source else 'DestinationAddress'} {resolved_ips[0]}")

    return ' '.join(result) if result else ''  # Return the result or an empty string if nothing is resolved

# Function to generate rules with multiple ports
def generate_rule(rule_name, source_param, destination_param, ports, protocol='Any'):
    # Check if there are multiple ports
    if isinstance(ports, list) and len(ports) > 1:
        port_param = f"@({','.join(ports)})"  # Join the ports as a PowerShell array without spaces
    else:
        port_param = f"'{ports[0]}'"  # Handle single port case

    return f"New-AzFirewallPolicyNetworkRule -Name {rule_name} {source_param} {destination_param} -DestinationPort {port_param} -Protocol '{protocol}'"

# Populate rule_collections based on policies_df
for _, row in policies_df.iterrows():
    name = row['Name']
    collection_name = name.split('_')[1] if len(name.split('_')) > 1 else 'default'
    if collection_name not in rule_collections:
        rule_collections[collection_name] = []
    rule_collections[collection_name].append(row)

# Create a list to hold the names of the rule collection variables
rule_collection_variable_names = []

for collection_name, rules in rule_collections.items():
    powershell_commands.append("")  # Add a blank line before the comment
    powershell_commands.append(f"# Create Rule Collection: {collection_name}")
    rule_collection_variable_name = f"$rc{collection_name}"
    rule_collection_variable_names.append(rule_collection_variable_name)  # Store the variable name
    powershell_commands.append(f"{rule_collection_variable_name} = New-AzFirewallPolicyFilterRuleCollection -Name '{collection_name}' -Priority {priority} -ActionType 'Allow' -Rule @(")

     # Increment the priority for the next collection
    priority += 100

    # Check to ensure the priority does not exceed 65000
    if priority > 65000:
        priority = 65000  # Reset or cap to maximum value as required

    # Append the sorted rules to the PowerShell script, referencing IP groups and individual IP addresses as necessary
    for rule in rules:
        source_address = rule['Source Address']
        destination_address = rule['Destination Address']
        rule_name = rule['Name']

        # Resolve addresses using resolve_address function, specifying whether it's source or destination
        source_param = resolve_address(source_address, is_source=True)
        destination_param = resolve_address(destination_address, is_source=False)

        # Use the service column to determine the port
        service_ports, protocol = resolve_service_ports(rule['Service'])

        # Append the rule command with proper indentation, using the PowerShell variable for IP groups and individual addresses
        powershell_commands.append(f"    {generate_rule(rule_name, source_param, destination_param, service_ports, protocol)}")

    powershell_commands.append(")")  # Closing the rule collection

# Convert the list of rule collection variable names into a PowerShell array
powershell_commands.append("")
powershell_commands.append(f"# Combine the rule collection variables into a single array")
powershell_commands.append(f"$allRuleCollections = @({', '.join(rule_collection_variable_names)})")

# Add the commit statement after all rule collections are processed
powershell_commands.append("") 
powershell_commands.append(f"# Commit changes to policy")
powershell_commands.append(f"Set-AzFirewallPolicyRuleCollectionGroup -Name $NetworkRuleCollectionGroup.Name -Priority 200 -RuleCollection $allRuleCollections -FirewallPolicyObject $fwPol")

# Write the PowerShell commands to a .ps1 file
with open('azure_firewall_policy.ps1', 'w') as ps_file:
    ps_file.write("\n".join(powershell_commands))

# Print a message indicating the script has been created
print("PowerShell script for Azure Firewall policy has been created")
