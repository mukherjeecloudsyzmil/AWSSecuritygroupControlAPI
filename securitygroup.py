from flask import Flask, render_template, request

import boto3

# Initialize Flask application
app = Flask(__name__)

# Initialize the Boto3 client for EC2
ec2_client = boto3.client('ec2')

# Define the ID of the security group you want to modify
security_group_id = 'sg-03124e013a54d8866'  # Replace with your security group ID

def get_existing_ip_port_pairs():
    response = ec2_client.describe_security_groups(GroupIds=[security_group_id])
    ip_permissions = response['SecurityGroups'][0]['IpPermissions']
    ip_port_pairs = []
    for permission in ip_permissions:
        ip_protocol = permission.get('IpProtocol')
        from_port = permission.get('FromPort')
        to_port = permission.get('ToPort')
        for ip_range in permission.get('IpRanges', []):
            cidr_ip = ip_range['CidrIp']
            ip_port_pairs.append((cidr_ip, ip_protocol, from_port, to_port))
    return ip_port_pairs

@app.route('/', methods=['GET', 'POST'])
def index():
    existing_ip_port_pairs = get_existing_ip_port_pairs()
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        port = int(request.form['port'])
        action = request.form['action']
        try:
            if action == 'add':
                # Authorize the ingress rule for the specified IP address and port
                response = ec2_client.authorize_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',  # Can be tcp, udp, icmp, etc.
                            'FromPort': port,  # Port range from
                            'ToPort': port,  # Port range to
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                message = "IP address added successfully."
            elif action == 'remove':
                # Revoke the ingress rule for the specified IP address and port
                response = ec2_client.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[
                        {
                            'IpProtocol': 'tcp',  # Can be tcp, udp, icmp, etc.
                            'FromPort': port,  # Port range from
                            'ToPort': port,  # Port range to
                            'IpRanges': [
                                {
                                    'CidrIp': ip_address + '/32'
                                },
                            ],
                        },
                    ]
                )
                message = "IP address removed successfully."
            existing_ip_port_pairs = get_existing_ip_port_pairs()
        except Exception as e:
            message = f"Error: {e}"
        return render_template('index.html', message=message, existing_ip_port_pairs=existing_ip_port_pairs)
    return render_template('index.html', existing_ip_port_pairs=existing_ip_port_pairs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
