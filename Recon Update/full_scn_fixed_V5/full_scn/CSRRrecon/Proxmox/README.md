# CSRRrecon Proxmox LXC Deployment Script

This script automates the deployment of CSRRrecon in a Linux Container (LXC) on a Proxmox server. It simplifies the process of setting up a dedicated environment for reconnaissance activities.

## Prerequisites

- A Proxmox VE server (version 6.x or later)
- Root access to the Proxmox server
- Sufficient storage space on the Proxmox server

## Usage

1. Copy the script `bash -c "$(curl -fsSL https://raw.githubusercontent.com/six2dez/CSRRrecon/master/Proxmox/CSRRrecon_prox_deploy.sh)"` to your Proxmox server.

4. Follow the prompts to configure your LXC container. You'll be asked for:
- Container ID
- Storage location
- Root filesystem size
- RAM allocation
- Number of CPU cores
- Hostname
- Password

5. The script will then:
- Download the Debian template if not already present
- Create and configure the LXC container
- Install CSRRrecon and its dependencies

6. Once completed, the script will display the container information, including ID, hostname, and password.

## Logging

The script generates a log file in `/var/log/` with the format `CSRRrecon_deploy_YYYYMMDD_HHMMSS.log`. Refer to this log for detailed information about the deployment process.

## Post-Installation

After the script completes:

1. You can access the container using:

```bash
pct enter <CONTAINER_ID>
```

2. CSRRrecon will be installed in `/opt/CSRRrecon/`. Navigate to this directory to use CSRRrecon.

3. Refer to the [CSRRrecon documentation](https://github.com/six2dez/CSRRrecon) for usage instructions.

## Troubleshooting

- If the script fails, check the log file for error messages.
- Ensure you have sufficient storage space and resources on your Proxmox server.
- Verify that your Proxmox server has internet access to download necessary packages.

## Security Note

Remember to change the default password after accessing the container for the first time.

## Support

For issues related to this deployment script, please open an issue in the GitHub repository. For CSRRrecon-specific questions, refer to the [CSRRrecon GitHub page](https://github.com/six2dez/CSRRrecon).