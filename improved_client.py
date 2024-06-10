from ast import dump
import copy
from http.clinet import HTTPConnection, HTTPSConnection
from urllib.parse import urlencode, urlparse
import ssl 
from typing import List, Union
from random import choice
from core import compute_decryption_factors
from some_module import get_random_selection, to_relative_answers
import sys
from http_utils import get_http_connection
from voter_file import generate_voter_file
from vote_generation import generate_vote
import logging
from typing import Optional
from urllib.parse import unquote, urlparse
from base64 import b64encode
import json
import os
import base64



def get_http_connection(url: str):

    ##Establishing a HTTP or HTTPS connection based on the given url

    parsed = urlparse(url)
    kwargs = {}
    if parsed.scheme == 'https':
            default_port = '443'
            Conn = HTTPSConnection
            kwargs['context'] = ssl._create_unverified_context()
    else:
            default_port = '80'
            Conn = HTTPConnection
    host, sep, port = parsed.netloc.partition(':')
    if not port:
        port = default_port
    netloc = host + ':' + port
    conn = Conn(netloc, **kwargs)
    conn.path = parsed.path
    return conn

def generte_voter_file(nr: int, domain, str = 'zeus.minedu.gov.gr'):
      
      ##Generate a string that represent a voter file.

      return '\n'.join((f"{i}, voter-{i}@{domain}, Ψηφοφόρος, {i}") for i in range(nr))


def generate_vote(p, g, q, y, choices: Union[int, List[int]], nr_candidates: int = None):
    ##Generate vote based on given choices

    if isinstance(choices, int):
          nr_candidates = choices
          selection = get_random_selection(nr_candidates, full=0)
    else:
          nr_candidates = nr_candidates or (max(choices) if choices else 0)
          selection = to_relative_answers(choices, nr_candidates)

    encoded = gamma_encode(selection, nr_candidates)
    ct = encrypt(encoded, p, g, q, y)
    alpha, beta, rand = ct
    proof = prove_encryption(p, g, q, alpha, beta, rand)
    commitment, challenge, response = proof
    answer = {}
    answer['encryption_proof'] = (commitment, challenge, response)
    answer['choices'] = [{'alpha': alpha, 'beta': beta}]
    encrypted_vote = {}
    encrypted_vote['answers'] = [answer]
    encrypted_vote['election_uuid'] = ''
    encrypted_vote['election_hash'] = ''
    return encrypted_vote, encoded, rand

def main_verify(sigfile: str, randomness: Optional[int] = None, plaintext: Optional[int] = None):
      logging.basicConfig(level=logging.INFO)

      try:
            with open(sigfile, 'r') as f: 
                  signature = f.read()
      except IOError as e:
            logging.error(f"Error reading signature file: {e}")
            return
      
      try:
            vote_info = verify_vote_signature(signature)
      except Exception as e:
        logging.error(f"Error verifying vote signature: {e}")
        return
      
      signed_vote, crypto, trustees, candidates, comments = vote_info

      eb = signed_vote['encrypted_ballot']
      public = eb['public']
      modulus, generator, order = crypto
      beta = eb['beta']
      logging.info('VERIFIED: Authentic Signature')

      if randomness is None:
            return
      
      nr_candidates  = len(candidates)

      try:
            encoded = decrypt_with_randomness(modulus, generator, order, public, beta, randomness)
      except Exception as e: 
            logging.error(f"Error during dectyprion: {e}")
            return
      
      if plaintext is not None:
        if plaintext != encoded:
             logging.warning('FAILED: Plaintext Mismatch')

        try:
             ct = encrypt(plaintext, modulus, generator, order, randomness)
             _alpha, _beta, _randomness = ct
             alpha = eb['alpha']
             if (alpha, beta) !=  (_alpha, _beta):
                  logging.warning('FAILED: Invalid Encryption')
        except Exception as e:
             logging.error(f"Error furing encryption")
             return
        
max_encoded = gamma_encoding = gamma_encoding_max(nr_candidates) + 1
logging.info(f"plaintext:         {encoded}")
logging.info(f"max plaintext:     {max_encoded}")
if encoded > max_encoded:
     logging.warning("FAILED: Invalid Vote. Cannot decode.")
     

try:
     selection = gamma_decode(encoded, nr_candidates)
     choices = to_absolute_answers(selection, nr_candidates)
except Exception as e:
     logging.error(f"Error during decoding: {e}")
     

logging.info("")
for i, o in enumerate(choices):
     logging.info(f"{i}: [{o}] {candidates[o]}")
logging.info("")
             

def get_http_connection(url):
     
     parsed_url = urlparse(url)
     conn = http.client.HTTPSConnection(parsed_url.netloc)
     return conn, parsed_url.path

def get_poll_info(url):
     conn = path = get_http_connection(url)

     try: 
          conn.request('GET', path)
          response = conn.getresponse()
          if response.status != 200:
               raise RuntimeError(f"failed to get initial response, status code: {response.status}")
          
          response.read()
          cookie = response.getheader('Set-Cookie')
          if not cookie:
               raise RuntimeError("Cannot get cookie")
          cookie = cookie.split(';')[0]
          headers = {'Cookie': cookie}

          poll_intro_path = '/' + poll_intro.split("/", 3)[3]
          conn.request('GET', poll_intro_path, headers=headers)
          response = conn.getresponse()
          if response.status != 200:
               raise RuntimeError(f"Failed to get poll introduction, status code: {response.status}")
          
          html = response.read().decode('utf-8')

          links_re = re.compile(r'href="(.*polls/.*/1/.*)"')
          links = links_re.findall(html)
          if not links:
               raise RuntimeError("No poll links found in the HTML")
          
          poll_id = path.split("/")[-2]
          poll_url = next((link fo link in links if poll_id in link), None)
          if not poll_url:
               raise RuntimeError("Poll URL not found in links")
          
          if 'link-to' in poll_url:
               conn.request('GET', poll_url, headers=headers)
               response = conn.getresponse()
               if response != 200:
                    raise RuntimeError(f"Failed to get link-to URL, status code: {response.status}")
               
               body = response.read()
               _headers = dict(response.getheaders())
               poll_url = _headers.get('Location')
               if not poll_url:
                    raise RuntimeError("Poll URL not found in response headers")
               
               parsed = urlparse(poll_url)
               poll_info = dict(parse_qsl(parsed.query))

               poll_json_url = poll_info.get('poll_json_url')
               if not poll_json_url:
                    raise RuntimeError("Poll JSON URL not found in poll information")
               
               
               poll_json_path = urlparse(poll_json_url).path
               conn.request('GET', poll_json_path, headers=headers)
               response = con.getresponse()
               if response.status !=200:
                    raise RuntimeError(f"Failed to get poll JSON data, status code: {response.status}")
               
               poll_info['poll_data'] = json.loads(response.read().decode('utf-8'))
               return conn, headers, poll_info
          
     except Exception as e:
          
          print(f"An error has occured: {e}")
          raise 
     finally:
          conn.close()


def extract_poll_info(poll_info):
     try:
          
          csrf_token = poll_info.get('token')
          if not csrf_token:
               raise ValueError("CSRF token is missing in poll_info")
          
          poll_data = poll_info.get('poll_data')
          if not poll_data:
               raise ValueError("Poll data is missing in poll_info")
          
          public_key = poll_data('public_key')
          if not public_key:
               raise ValueError("Public key is missing in poll_data")
          
          p = int(public_key.get('p', 0))
          g = int(public_key.get('g', 0))
          q = int(public_key.get('q', 0))
          y = int(public_key.get('y', 0))
          
          if not all([p, g, q, y]):
               raise ValueError("One or more public key components are missing or invalid")
          
          questions = poll.data.get('questions')
          if not questions or len(questions) == 0:
               raise ValueError("Questions are missin in poll_data")
          
          
          answers = question[0].get('answers')
          if not answers:
               raise ValueError('Answers are missing in the first question of poll_data')
          
          cast_path = poll_data.get('cast_url')
          if not cast_path:
               raise ValueError('Cast URL is missing in poll_data')
          
          return cast_path, csrf_token, answers, p, g, q, y
     
     except Exception as e:
          print(f"An error occured while extracting poll information: {e}")
          raise
     

def do_cast_vote(conn, cast_path, token, headers, vote):
     try:
          
          body = urlencode({
               'encrypted_vote': json.dumps(vote),
               'csrfmiddlewaretoken': token
          })

          conn.request('POST', cast_path, body = body, headers = headers)
          response = conn.getresponse()

          response_body = response.read()

          if response.status != 200:
               raise RuntimeError(f"Failed to cast vote, status code: {response.status}")
          
          return response_body.decode('utf-8')
     
     except Exception as e:
          print(f"An error occured while casting the vote: {e}")
          raise
     
     finally:
          
          conn.close()

def _make_vote(poll_data, choices = None):
     try:
          pk = poll_data['public_key']
          p = int(pk['p'])
          g = int(pk['g'])
          q = int(pk['q'])
          y = int(pk['y'])

          candidates = poll_data['questions'][0]['answers']

          parties = None
          try:
               parties, nr_groups = parties_from_candidates(candidates)
          except FormatError as e:
               parties = None

          if parties:
               if randint(0, 19) == 0:
                    choices = []
               else:
                party_choice = choice(list(parties.keys()))
                party = parties[party_choice]
                party_candidates = [k for k in party.keys() if isinstance(k, int)]
                min_choices = party['opt_min_choices']
                max_choices = party['opt_max_choices']
                shuffle(party_candidates)
                nr_choices = randint(min_choices, max_choices)
                choices = party_candidates[:nr_choices]
                choices.sort()

                vote, encoded, rand = generate_vote(p, g, q, y, choices, len(candidates))
        
                for c in choices: 
                     print(f"Voting for {c}, {party[c]}")

                ballot = gamma_encode_to_party_ballot(encoded, candidates, parties, nr_groups)
                
                if not ballot['valid']:
                     print(f"Ballot invalid: {ballot['invalid_reason']}")
                else:
                     choices = choices if choices is not None else list(range(len(candidates)))
                     vote, encoded, rand = generate_vote(p, g, q, y, choices)

                return vote, encoded, rand
               
     except Exception as e:
          print(f'An error occured while making the vote: {e}')
          raise
     

def cast_vote(voter_url, choices=None):
     try:
          
          conn, headers, poll_info = get_poll_info(voter_url)
          csfr_token = poll_info['token']


          headers['Cookie'] += f"; csfrtoken={csfr_token}"
          headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
          headers['Referer'] = voter_url

          vote, encoded, rand, = _make_vote(poll_info['poll_data'], choices)
          cast_path = poll_info['poll_data']['cast_url']

          do_cast_vote(conn, cast_path, csfr_token, headers, vote)

          return encoded, rand
     
     except Exception as e:
        print(f"An error occurred while casting the vote: {e}")
        raise


def main_generate(nr, domain, voters_file):
     if os.path.exists(voters_file):
          raise ValueError(f"{voters_file}: file exists, will not overwrite")
     
     with open(voters_file, 'w', encoding='utf-8') as f:
          voter_data = generate_voter_file(nr, domain=domain)
          f.write(voter_data)

def main_random_cast_thread(inqueue, outqueue):
     while True:
          try:
               task = inqueue.get_nowait()
               if not task:
                    break
          except Empty:
               break
          
          i, total, voter_url = task
          print(f"{i+1}/{total}")
          encoded, rand = cast_vote(voter_url)
          outqueue.put(encoded)    

def main_random_cast(voter_url_file, plaintexts_file, nr_threads=2):
     if os.path.exists(plaintexts_file):
          raise ValueError(f"{plaintexts_file}: file exists, will not overwrite")

     with open(plaintexts_file, "w") as f: 
        
        voter_urls = open(voter_url_file).read().splitlines()
        total = len(voter_urls)
        inqueue = Queue(maxsize=total)
        outqueue = Queue(maxsize=total)  
                    
        for i, voter_url in enumerate(voter_urls):
             inqueue.put((i, total, voter_url))

        threads = [Thread(target=main_random_cast_thread, args=(inqueue, outqueue)) for _ in range(nr_threads)]

        for t in threads: 
             t.daemon = True
             t.start()

        plaintexts = [outqueue.get(0 for _ in range(total))]
        f.write(json.dumps(plaintexts))

        for t in threads:
             t.join()


def main_show(url):
     conn, cast_path, token, headers, answers, p, g, q, y, = get_election(url)
     for i, candidate in enumerate(answers):
          if isinstance(candidate, str):
               candidate = candidate.encode('utf-8')
               print(f"{i}: candidate")


def main_vote(url, choice_str):
     choices = [int(x) for x in choice_str.split(',')]
     encoded, rand = cast_vote(url, choices)
     print(f"Encoded selection, {encoded}")
     print(f"Encryption randomness: {rand}")

def do_download_mix(url, savefile):
     if os.path.exists(savefile):
          raise ValueError(f"File '{savefile}' already exists, will not overwrite")
     
     conn = get_http_connection(url)
     conn.request('GET', conn.path)
     response = conn.getresponse()
     save_data = response.read().decode('utf-8')

     if "polls" not in url:
          polls = json.loads(save_data)
          for i, poll_url in enumerate(polls):
               do_download_mix(poll_url, f"{savefile}.{i}")
          return
     
     with open(savefile, "w", encoding='utf-8') as f:
          f.write(save_data)

     return save_data


def get_login(url):
     url = unquote(url)
     conn = get_http_connection(url)
     parsed = urlparse(url)

     path_parts = parsed.path.split("/")
     _, _, election, _, _, trustee, password = path_parts[-7:]
     prefix = "/".join(path_parts[:-6])
     auth = b64encode(f"{election}:{trustee}:{password}".encode()).decode()
     headers = {
          'Authorization': f'Basic {auth}'
     }
     base_url = f"{prefix}/elections/{election}/trustee"
     return conn, headers, base_url


def get_election_info(url):
    conn, headers, url = get_login(url)
    conn.request('GET', url + '/json', headers=headers)
    resp = json.loads(conn.getresponse().read().decode('utf-8'))
    return resp

def do_download_ciphers(url, savefile):
     info = get_election_info(url)
     save_data = None

     for i, poll in enumerate(info['election']['polls']):
          curr_file = f"{savefile}.{i}"
          if os.path.exists(curr_file):
               print(f"File '{curr_file}' already exists, will not overwrite")
               continue

          conn, headers, _ = get_login(url)
          download_url = urlparse(poll['ciphers_url']).path
          conn.request('GET', download_url, headers=headers)
          response = conn.getresponse()
          save_data = response.read().decode('utf-8')

          with open(curr_file, "w", encoding='utf-8') as f:
               f.write(save_data)

     return save_data


def do_upload_mix(savefile, url):
     if "polls" not in url:
        polls = loads(save_data)
        conn = get_http_connection(url)
        conn.request('GET', conn.path)
        response = conn.getresponse()
        save_data = response.read()

        for i, url in enumerate(polls):
            do_download_mix(url, "{}.{}".format(savefile, i))
            return
        
     with open(savefile, "w") as f:
          f.write(save_data)

     return save_data

def get_login(url):
     try:
          url = unquote(url)

          conn = get_http_connection(url)

          parsed = urlparse(url)

          path_parts = parsed.path.split("/")
          if len(path_parts) < 7:
               raise ValueError("URL path does not contain enough parts")
          
          _, _, election, _, _, trustee, password = path_parts[-7:]
          prefix = "/".join(path_parts[:-6])

          auth = base64.b64encode(f"{election}:{trustee}:{password}".encode('utf-8')).decode('utf-8')

          headers = {
            'Authorization': f'Basic {auth}'
        }
        
        # Construct base URL
          base_url = f"{prefix}/elections/{election}/trustee"

          return conn, headers, base_url
     except Exception as e:
          print(f"Error occured: {e}")
          return None, None, None
     
def get_election_info(url):
    conn, headers, url = get_login(url)
    conn.request('GET', url + '/json', headers=headers)
    resp = loads(conn.getresponse().read())
    return resp

def do_download_ciphers(url, savefile):
    try:
        save_data = None

        info = get_election_info(url)
        if not info or 'election' not in info or 'polls' not in info['election']:
            raise ValueError("Invalid election information")
        
        for i, poll in enumerate(info['election']['polls']):
            curr_file = f"{savefile}.{i}"
            if os.path.exists(curr_file):
                 sys.stdout.write(f"File '{curr_file}, already exists, will not overwrite")
            continue

        conn, headers, base = get_login(url)
        if not conn or not headers or not base:
             raise ConnectionError("Failed to get login details")
        
        download_url = urlparse(poll['ciphers_url']).path
        conn.request('GET', download_url, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            raise IOError(f"Failed to download data, status code: {response.status}")

        save_data = response.read()
        with open(curr_file, "wb") as f:
             f.write(save_data)

        return save_data
    except Exception as e:
         print(f"Error occured: {e}")
         return None

def do_upload_mix(outfile, url):
    try:
        # Check if the URL does not contain "polls"
        if "polls" not in url:
            conn = get_http_connection(url)
            conn.request('GET', urlparse(url).path)
            response = conn.getresponse()
            if response.status != 200:
                raise IOError(f"Failed to retrieve polls, status code: {response.status}")
            polls = json.loads(response.read())
            for i, poll in enumerate(polls):
                do_upload_mix(f"{outfile}.{i}", poll)
            return
        
        if not os.path.exists(outfile):
             raise FileNotFoundError(f"File '{outfile}' does not exist")
        
        with open(outfile, 'r') as f:
            out_data = f.read()

        conn = get_http_connection(url)
        conn.request('POST', urlparse(url).path, body=out_data)
        response = conn.getresponse()
        if response.status != 200:
            raise IOError(f"Failed to upload data, status code: {response.status}")

        print(response.status, response.read())
    except Exception as e:
        print(f"Error occurred: {e}")

def do_upload_factors(curr_file):
     try:
          with open(curr_file, 'r') as f: 
               out_data = f.read()
          
          info = get_election_info(url)
          path = urlparse(logging.info['election']['polls'][poll_index]['post_decryption_url']).path

          conn, headers, redirect = get_login(url)
          body = urlencode({'factors_and_proofs': out_data})
          headers = copy.deepcopy(headers)
          headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'

          conn.request('POST', path, body=body, headers=headers)
          response = conn.getresponse()
          print(response.read()) 

     except Exception as e:
          print(f"Error processing file {curr_file}: {e}")

          poll_index += 1
          curr_file = f"{outfile}.{poll_index}"


def do_automix(url, prefix, nr_rounds, nr_parallel, module):
    do_download_mix(url, "{}-votes".format(prefix))
    do_mix("{}-votes".format(prefix), "{}-mix".format(prefix), nr_rounds,
            nr_parallel, module)
    do_upload_mix("{}-mix".format(prefix), url)

def do_mix(mixfile, newfile, nr_rounds, nr_parallel, module):
     if os.path.exists(newfile):
          raise ValueError(f"File '{newfile}' already exists, will not overwrite")
     
     if os.path.exists(f"{mixfile}.0"):
          i = 0
          while os.path.exists(f"{mixfile}.{i}"):
               do_mix(f"{mixfile}.{i}", f"{newfile=}.{i}", nr_rounds, nr_parallel, module)
               i += 1
          return
     
     try:
     
        with open(mixfile) as f:
            mix = from_canonical(f)
     except Exception as e:
          raise ValueError(f"Failed to read mixfile '{mixfile}': {e}")

     try: 
        new_mix = module.mix_ciphers(mix, nr_rounds=nr_rounds,
                          nr_parallel=nr_parallel)
     except Exception as e:
        raise ValueError(f"Failed to mix ciphers: {e}")

     try:
        with open(newfile, "w") as f:
            to_canonical(new_mix, out=f)
     except Exception as e:
        raise ValueError(f"Failed to write to newfile '{newfile}': {e}")
     
     return new_mix

def main_help():
    usage = ("Usage: {0} generate <nr> <domain> <voters.csv>\n"
             "       {0} masscast <voter_url_file> <plaintexts_file> [nr_threads]\n"
             "       {0} show     <voter_url>\n"
             "       {0} castvote <voter_url> <1st>,<2nd>,... (e.g.)\n"
             "       {0} verify   <vote_signature_file> [randomness [plaintext]]\n"
             "\n"
             "       {0} download mix <url> <input.mix>\n"
             "       {0} mix          [<url> <mix-name>|<input.mix> <output.mix>] <nr_rounds> <nr_parallel>\n"
             "       {0} upload mix   <output.mix> <url>\n"
             "\n"
             "       {0} download ciphers <url> <ballots_savefile>\n"
             "       {0} decrypt          <ballots_savefile> <factors_outfile> <key_file> <nr_parallel>\n"
             "       {0} upload factors   <factors_outfile> <url>\n".format(sys.argv[0]))
    sys.stderr.write(usage)
    raise SystemExit

def do_decrypt(savefile: str, outfile: str, keyfile: str, nr_parallel: int) -> Any:
    poll_index = 0
    curr_file = f"{savefile}.0"

    try:
        with open(keyfile, 'r') as f:
            key = json.load(f)
    except Exception as e:
        raise ValueError(f"Failed to load keyfile '{keyfile}': {e}")

    try:
        secret = int(key['x'])
        pk = key['public_key']
        modulus = int(pk['p'])
        generator = int(pk['g'])
        order = int(pk['q'])
        public = int(pk['y'])
    except KeyError as e:
        raise ValueError(f"Invalid key format: missing {e}")
    finally:
        del key

    while os.path.isfile(curr_file):
        curr_outfile = f"{outfile}.{poll_index}"

        if os.path.exists(curr_outfile):
            sys.stderr.write(f"File '{curr_outfile}' already exists, will not overwrite\n")
            poll_index += 1
            curr_file = f"{savefile}.{poll_index}"
            continue

        try:
            with open(curr_file, 'r') as f:
                tally = json.load(f)['tally']
        except Exception as e:
            raise ValueError(f"Failed to load tally file '{curr_file}': {e}")

        ciphers = [(int(ct['alpha']), int(ct['beta'])) for ct in tally['tally'][0]]
        
        try:
            factors = compute_decryption_factors(modulus, generator, order, secret, ciphers, nr_parallel=nr_parallel)
        except Exception as e:
            raise ValueError(f"Failed to compute decryption factors: {e}")

        decryption_factors = [factor for factor, _ in factors]
        decryption_proofs = [{
            'commitment': {'A': proof[0], 'B': proof[1]},
            'challenge': proof[2],
            'response': proof[3]
        } for _, proof in factors]

        factors_and_proofs = {
            'decryption_factors': [decryption_factors],
            'decryption_proofs': [decryption_proofs]
        }

        try:
            with open(curr_outfile, 'w') as f:
                dump(factors_and_proofs, f)
        except Exception as e:
            raise ValueError(f"Failed to write to outfile '{curr_outfile}': {e}")

        poll_index += 1
        curr_file = f"{savefile}.{poll_index}"

    return factors

def main(argv=None):
    argv = argv or sys.argv
    argc = len(argv)

    if argc < 2:
        main_help()
        return

    cmd = argv[1]

    cmd_functions = {
        'download': handle_download,
        'upload': handle_upload,
        'mix': handle_mix,
        'decrypt': handle_decrypt,
        'generate': handle_generate,
        'masscast': handle_masscast,
        'show': handle_show,
        'castvote': handle_castvote,
        'verify': handle_verify
    }

    if cmd in cmd_functions:
        cmd_functions[cmd](argv)
    else:
        main_help()

def handle_download(argv):
    if len(argv) < 5:
        main_help()
        return

    if argv[2] == 'mix':
        do_download_mix(argv[3], argv[4])
    elif argv[2] == 'ciphers':
        do_download_ciphers(argv[3], argv[4])
    else:
        main_help()

def handle_upload(argv):
    if len(argv) < 5:
        main_help()
        return

    if argv[2] == 'mix':
        do_upload_mix(argv[3], argv[4])
    elif argv[2] == 'factors':
        do_upload_factors(argv[3], argv[4])
    else:
        main_help()

def handle_mix(argv):
    if len(argv) < 6:
        main_help()
        return

    import zeus_sk as shuffle_module

    if argv[2].startswith("http"):
        do_automix(argv[2], argv[3], int(argv[4]), int(argv[5]), shuffle_module)
    else:
        do_mix(argv[2], argv[3], int(argv[4]), int(argv[5]), shuffle_module)

def handle_decrypt(argv):
    if len(argv) < 6:
        main_help()
        return

    do_decrypt(argv[2], argv[3], argv[4], int(argv[5]))

def handle_generate(argv):
    if len(argv) < 5:
        main_help()
        return

    main_generate(int(argv[2]), argv[3], argv[4])

def handle_masscast(argv):
    if len(argv) < 4:
        main_help()
        return

    nr_threads = int(argv[4]) if len(argv) > 4 else 2
    main_random_cast(argv[2], argv[3], nr_threads=nr_threads)

def handle_show(argv):
    if len(argv) < 3:
        main_help()
        return

    main_show(argv[2])

def handle_castvote(argv):
    if len(argv) < 3:
        main_help()
        return

    if len(argv) == 3:
        main_show(argv[2])
    else:
        main_vote(argv[2], ''.join(argv[3:]))

def handle_verify(argv):
    if len(argv) < 3:
        main_help()
        return

    randomness = None if len(argv) < 4 else int(argv[3])
    plaintext = None if len(argv) < 5 else int(argv[4])
    main_verify(argv[2], randomness, plaintext)

if __name__ == '__main__':
    main()







          
          


        