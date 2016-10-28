Project: Linux Server Configuration - Shumei Lin

- IP Address: http://35.160.183.100
- URL: http://ec2-35-160-183-100.us-west-2.compute.amazonaws.com
- Sotware installed:

	apache2
	
	mod-wsgi
	
	PostgreSQL
	
	Flask
	
	pip

- Configuration made:
	Changed ssh port from 22 to 2200.
	
	Configured firewall to only allow connections for SSH (port 2200), HTTP (port 80), and NTP (port 123).
	
	Created new user grader with sudo access.
	
	Remote login of the root user is disabled.
	
	Key-based SSH authentication is enforced.
	
	Configured local time to UTC.
	
	Configured and enabled a new virtual host in /etc/apache2/sites-available/catalog.conf.
	
	Created a catalog.wsgi file to serve the catalog app with flask and python.

- Third party resources used:

	https://www.digitalocean.com/community/tutorials/how-to-deploy-a-flask-application-on-an-ubuntu-vps
	
	https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-ubuntu-14-04
	
	https://www.digitalocean.com/community/tutorials/how-to-use-roles-and-manage-grant-permissions-in-postgresql-on-a-vps--2
