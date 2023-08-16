#Secure way to see if password has ever been hacked

import requests
import hashlib
import sys 
import getpass

#Hides terminal input in terminal as added security.
hidden_pass = getpass.getpass('Enter Password:')

""" The first function of this program takes the url of an api and string and sets them 
to a variable. The get module is then used to retrieve the url and queried character. res is created as a shorthand variable
to encapsulate our http request object with our url object. It raises a runtime error if the api is not equal to the standard
status code and returns the response object"""

def request_api_data(search_char):
	url = 'https://api.pwnedpasswords.com/range/' + search_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching:{res.status_code}, check the api and try again.')
	return res

""" The next function of this program takes in hash values, splits them with a colon and uses 
the splitline module to place each line into a list. """

def get_pass_leak_count(hashes, hashes_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hashes_to_check:
			return count
	return 0 

""" The next function takes in a password as parameter, then uses the sha1 encyrption method to safely secure the inputed string, 
and the hexidigest module to aid in alphanumerical enycrption. We then want to create another level of privacy by only displaying the first
five digits of encyrpted password. We take that and the subsequent rest of the password and put those into the first five and tail variables.
It is then necessary to send the first 5 digits to the request api function which returns a response object that is encapsulated in a variable. 
Finally the response object and tail hashtable value is sent to the counting function which counts any matches and then returns that count by 
incrimenting over two variables simultaneously one for comparison and one for measurement. 
"""

def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first_5_char, tail, = sha1password[:5],sha1password[5:], 
	response = request_api_data(first_5_char)
	return get_pass_leak_count(response,tail)


""" Our main function then takes in the hidden password passed on from the terminal.
Next, take that count object we created and returned in our pwnned api check function and then use a comparitive statement to
assess if the password was found by the api, returning a finito string upon completion.
"""

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f' Found {count} times. For your safety change your password at your earliest convenience.')
		else:
			print('Not found. Stay vigilent.')
	return 'Finito.'

#Execution
if __name__ == '__main__':
	sys.exit(main([hidden_pass]))

