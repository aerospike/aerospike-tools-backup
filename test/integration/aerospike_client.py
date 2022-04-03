# coding=UTF-8

"""
Aerospike client management utilities.
"""

CLIENT = None

def validate_client():
	"""
	Make sure that there is a client.
	"""
	assert CLIENT is not None, "No client"

def get_client():
	return CLIENT

def set_client(client):
	global CLIENT
	CLIENT = client

