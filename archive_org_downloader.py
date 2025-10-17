import requests
import random, string
from concurrent import futures
from tqdm import tqdm
import time
from datetime import datetime
import argparse
import os
import sys
import shutil
import json
import re
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

# --- Existing Helper Functions (omitted for brevity, assume they are present) ---

def display_error(response, message):
	print(message)
	print(response)
	print(response.text)
	# Changed exit() to raise an exception for better GUI handling
	raise Exception(message) 

def get_book_infos(session, url):
	r = session.get(url).text
	# ... (existing logic)
	infos_url = "https:" + r.split('"url":"')[1].split('"')[0].replace("\\u0026", "&")
	response = session.get(infos_url)
	data = response.json()['data']
	title = data['brOptions']['bookTitle'].strip().replace(" ", "_")
	title = ''.join( c for c in title if c not in '<>:"/\\|?*' )
	title = title[:150]
	metadata = data['metadata']
	links = []
	for item in data['brOptions']['data']:
		for page in item:
			links.append(page['uri'])

	if len(links) > 1:
		print(f"[+] Found {len(links)} pages")
		return title, links, metadata
	else:
		print(f"[-] Error while getting image links")
		raise Exception("Error while getting image links")

def login(email, password):
	session = requests.Session()
	session.get("https://archive.org/account/login")

	data = {"username":email, "password":password}

	response = session.post("https://archive.org/account/login", data=data)
	if "bad_login" in response.text:
		raise Exception("Invalid credentials!")
	elif "Successful login" in response.text:
		print("[+] Successful login")
		return session
	else:
		display_error(response, "[-] Error while login:")

def loan(session, book_id, verbose=True):
	data = {
		"action": "grant_access",
		"identifier": book_id
	}
	response = session.post("https://archive.org/services/loans/loan/searchInside.php", data=data)
	data['action'] = "browse_book"
	response = session.post("https://archive.org/services/loans/loan/", data=data)

	if response.status_code == 400 :
		try:
			if response.json()["error"] == "This book is not available to borrow at this time. Please try again later.":
				if verbose:
					print("This book doesn't need to be borrowed")
				return session
			else :
				display_error(response, "Something went wrong when trying to borrow the book.")
		except:
			display_error(response, "The book cannot be borrowed")

	data['action'] = "create_token"
	response = session.post("https://archive.org/services/loans/loan/", data=data)

	if "token" in response.text:
		if verbose:
			print("[+] Successful loan")
		return session
	else:
		display_error(response, "Something went wrong when trying to borrow the book, maybe you can't borrow this book.")

def return_loan(session, book_id):
	data = {
		"action": "return_loan",
		"identifier": book_id
	}
	response = session.post("https://archive.org/services/loans/loan/", data=data)
	if response.status_code == 200 and response.json()["success"]:
		print("[+] Book returned")
	else:
		display_error(response, "Something went wrong when trying to return the book")

def image_name(pages, page, directory):
	return f"{directory}/{(len(str(pages)) - len(str(page))) * '0'}{page}.jpg"

def deobfuscate_image(image_data, link, obf_header):
	"""@Author: https://github.com/justimm"""
	try:
		version, counter_b64 = obf_header.split('|')
	except Exception as e:
		raise ValueError("Invalid X-Obfuscate header format") from e

	if version != '1':
		raise ValueError("Unsupported obfuscation version: " + version)

	aesKey = re.sub(r"^https?:\/\/.*?\/", "/", link)
	sha1_digest = hashlib.sha1(aesKey.encode('utf-8')).digest()
	key = sha1_digest[:16]

	counter_bytes = base64.b64decode(counter_b64)
	if len(counter_bytes) != 16:
		raise ValueError(f"Expected counter to be 16 bytes, got {len(counter_bytes)}")

	prefix = counter_bytes[:8]
	initial_value = int.from_bytes(counter_bytes[8:], byteorder='big')

	ctr = Counter.new(64, prefix=prefix, initial_value=initial_value, little_endian=False)
	cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

	decrypted_part = cipher.decrypt(image_data[:1024])
	new_data = decrypted_part + image_data[1024:]
	return new_data	

def download_one_image(session, link, i, directory, book_id, pages):
	headers = {
		"Referer": "https://archive.org/",
		"Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
		"Sec-Fetch-Site": "same-site",
		"Sec-Fetch-Mode": "no-cors",
		"Sec-Fetch-Dest": "image",
	}
	retry = True
	response = None
	while retry:
		try:
			response = session.get(link, headers=headers)
			if response.status_code == 403:
				session = loan(session, book_id, verbose=False)
				raise Exception("Borrow again")
			elif response.status_code == 200:
				retry = False
		except Exception as e:
			if str(e) != "Borrow again":
				time.sleep(1)
			else:
				time.sleep(1)

	image = image_name(pages, i, directory)

	image_content = response.content
	obf_header = response.headers.get("X-Obfuscate")
	if obf_header:
		try:
			image_content = deobfuscate_image(response.content, link, obf_header)
		except Exception as e:
			print(f"[ERROR] Deobfuscation failed for page {i}: {e}")
			return
	
	with open(image, "wb") as f:
		f.write(image_content)

def download(session, n_threads, directory, links, scale, book_id):
	print("Downloading pages...")
	links = [f"{link}&rotate=0&scale={scale}" for link in links]
	pages = len(links)

	tasks = []
	with futures.ThreadPoolExecutor(max_workers=n_threads) as executor:
		for link in links:
			i = links.index(link)
			tasks.append(executor.submit(download_one_image, session=session, link=link, i=i, directory=directory, book_id=book_id, pages=pages))
		for task in tqdm(futures.as_completed(tasks), total=len(tasks)):
			try:
				task.result()
			except Exception as e:
				print(f"Error in download task: {e}")
				
	
	images = [image_name(pages, i, directory) for i in range(len(links))]
	images = [img for img in images if os.path.exists(img)]
	return images

def make_pdf(pdf, title, directory):
	file = title+".pdf"
	i = 1
	while os.path.isfile(os.path.join(directory, file)):
		file = f"{title}({i}).pdf"
		i += 1

	with open(os.path.join(directory, file),"wb") as f:
		f.write(pdf)
	print(f"[+] PDF saved as \"{file}\"")

# --- CORE LOGIC WRAPPER FUNCTION ---

def run_downloader(email, password, urls, file_path, directory, resolution, threads, is_jpg, is_meta):
	"""
	Main logic of the downloader script, accepts arguments instead of reading from command line.
	Returns True on success, False on failure.
	"""

	# 1. Setup/Validation
	d = directory if directory is not None else os.getcwd()

	if not os.path.isdir(d):
		print(f"Output directory does not exist!")
		return False

	# Handle URLs from a file if file_path is provided
	if urls is None and file_path is not None:
		if os.path.exists(file_path):
			with open(file_path) as f:
				urls = [u.strip() for u in f.read().strip().split("\n") if u.strip()]
		else:
			print(f"URL list file '{file_path}' does not exist!")
			return False
	elif urls is None:
		print("At least one URL or a file path is required.")
		return False
	
	# Ensure urls is a list if it was a single string from a single URL input
	if not isinstance(urls, list):
		urls = [urls]

	# Check the urls format
	for url in urls:
		if not url.startswith("https://archive.org/details/"):
			print(f"{url} --> Invalid url. URL must starts with \"https://archive.org/details/\"")
			return False
	
	scale = resolution
	n_threads = threads

	print(f"{len(urls)} Book(s) to download")
	
	try:
		session = login(email, password)
	except Exception as e:
		print(f"Login failed: {e}")
		return False

	# 2. Download Loop
	for url in urls:
		book_id = list(filter(None, url.split("/")))[3]
		print("="*40)
		print(f"Current book: https://archive.org/details/{book_id}")

		directory = None # Initialize directory for cleanup
		loaned = False
		try:
			session = loan(session, book_id)
			loaned = True
			title, links, metadata = get_book_infos(session, url)

			directory = os.path.join(d, title)
			
			i = 1
			_directory = directory
			while os.path.isdir(directory):
				directory = f"{_directory}({i})"
				i += 1
			os.makedirs(directory)
			
			if is_meta:
				print("Writing metadata.json...")
				with open(f"{directory}/metadata.json",'w') as f:
					json.dump(metadata,f, indent=4) # Added indent for readability

			images = download(session, n_threads, directory, links, scale, book_id)

			if not is_jpg:
				import img2pdf

				# prepare PDF metadata
				pdfmeta = { }
				for key in ["title", "creator", "associated-names"]:
					if key in metadata:
						if isinstance(metadata[key], str):
							pass
						elif isinstance(metadata[key], list):
							metadata[key] = "; ".join(metadata[key])
						else:
							raise Exception("unsupported metadata type")
				if 'title' in metadata:
					pdfmeta['title'] = metadata['title']
				if 'creator' in metadata and 'associated-names' in metadata:
					pdfmeta['author'] = metadata['creator'] + "; " + metadata['associated-names']
				elif 'creator' in metadata:
					pdfmeta['author'] = metadata['creator']
				elif 'associated-names' in metadata:
					pdfmeta['author'] = metadata['associated-names']
				if 'date' in metadata:
					try:
						date_str = metadata['date'] if isinstance(metadata['date'], str) else metadata['date'][0] 
						pdfmeta['creationdate'] = datetime.strptime(date_str[0:4], '%Y')
					except:
						pass
				pdfmeta['keywords'] = [f"https://archive.org/details/{book_id}"]

				pdf = img2pdf.convert(images, **pdfmeta)
				make_pdf(pdf, title, d)
				try:
					shutil.rmtree(directory)
				except OSError as e:
					print ("Error: %s - %s." % (e.filename, e.strerror))
		
		except Exception as e:
			print(f"An error occurred while processing {url}: {e}")
			# Clean up temporary directory if it was created
			if directory and os.path.isdir(directory):
				try:
					shutil.rmtree(directory)
					print(f"Cleaned up temporary directory: {directory}")
				except:
					pass
		finally:
			if loaned:
				try:
					return_loan(session, book_id)
				except Exception as e:
					print(f"Failed to return loan for {book_id}: {e}")

	print("\nDownload process finished.")
	return True

# --- COMMAND LINE ENTRY POINT (calls run_downloader) ---

if __name__ == "__main__":
	# This block remains dedicated to command line argument parsing
	my_parser = argparse.ArgumentParser()
	my_parser.add_argument('-e', '--email', help='Your archive.org email', type=str, required=True)
	my_parser.add_argument('-p', '--password', help='Your archive.org password', type=str, required=True)
	my_parser.add_argument('-u', '--url', help='Link to the book (https://archive.org/details/XXXX). You can use this argument several times to download multiple books', action='append', type=str)
	my_parser.add_argument('-d', '--dir', help='Output directory', type=str)
	my_parser.add_argument('-f', '--file', help='File where are stored the URLs of the books to download', type=str)
	my_parser.add_argument('-r', '--resolution', help='Image resolution (10 to 0, 0 is the highest), [default 3]', type=int, default=3)
	my_parser.add_argument('-t', '--threads', help="Maximum number of threads, [default 50]", type=int, default=50)
	my_parser.add_argument('-j', '--jpg', help="Output to individual JPG's rather than a PDF", action='store_true')
	my_parser.add_argument('-m', '--meta', help="Output the metadata of the book to a json file (-j option required)", action='store_true')

	if len(sys.argv) == 1:
		my_parser.print_help(sys.stderr)
		sys.exit(1)
	args = my_parser.parse_args()

	if args.url is None and args.file is None:
		my_parser.error("At least one of --url and --file required")

	# CALL THE WRAPPED FUNCTION with command line arguments
	run_downloader(
		email=args.email,
		password=args.password,
		urls=args.url,
		file_path=args.file,
		directory=args.dir,
		resolution=args.resolution,
		threads=args.threads,
		is_jpg=args.jpg,
		is_meta=args.meta
	)
