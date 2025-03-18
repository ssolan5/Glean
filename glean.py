from datetime import datetime
import aiohttp
import argparse
import whois
import json
import logging
import ipaddress
import socket
import vt
import asyncio
import sys,os
import re
import time

apikey = None

logger = logging.getLogger(__name__)
logging.basicConfig(filename='main.log', filemode='w', encoding='utf-8', level=logging.DEBUG)

async def queue_addresses(queue, url):

    logger.info("Queuing...")  
 
    if type(url) is str:

        await queue.put(url)

    elif type(url) is list:

        for _url in url:
            await queue.put(_url)


async def async_queue_whois_lookup(queue, whois_json):

    while not queue.empty():

        try:
 
            url = await queue.get()
            print("Getting whois for: " + url)
 
            whois_data = whois.whois(url)
            whois_json[str(url)] = dict(whois_data)
            print("Received whois information for: " + url)
            logger.info("Received whois information for: " + url)

        except Exception as error:

            logger.exception("Python-whois API call returned an error: " + type(error))
 

async def async_vt_get_url(url_id):


    async with aiohttp.ClientSession() as session:
        headers = {
                "accept" : "application/json",
                "x-apikey" : str(apikey) 
        }
        async with session.get("https://www.virustotal.com/api/v3/urls/" + url_id, headers=headers) as response:
 
            json_object = await response.json()
            return json_object


async def async_queue_vt_lookup_url(queue, vt_json):


    async with vt.Client(str(apikey)) as client:
        while not queue.empty():

            url = await queue.get()
 
            logger.info("Found a url in the queue: " + url)
            print("Found a url in the queue: " + url)

            try: 

                analysis = await client.scan_url_async(url)
                vt_object = dict()
                vt_object["analysis"] = analysis.to_dict()
                url_id = vt.url_id(url)
                url_object = await async_vt_get_url(url_id)
                vt_object["URL object"] = url_object
                vt_json[str(url)] = vt_object

                logger.info( "Virus Total JSON response received for " + url )
                print("Virus Total JSON response received for " + url)

            except Exception as error:

                logger.exception( "VirusTotal request threw an exception : "+ str(error) ) 
            

def handle_api(args):

    # Parsing JSON manually
 
    json_string = args.api.strip("{}")
    json_dict = dict()

    if len(json_string.split(", ")) == 1 :

        json_dict['ipaddress'] = (json_string.split(":"))[1]

    else:

        json_dict = dict(item.split(": ") for item in json_string.split(", "))
 
    logger.error(json_dict)
 
    json_list = list()

    for keys in json_dict.keys():

        value = json_dict.get(keys)

        # Trimming whitespace 
        value = value.strip(" ")

        # Removing extra quotes 
        value = value.replace("\"","")  


        if validate("ipaddress:"+value):
            json_list.append(value)
        else:
            logger.error("JSON IP address or URL not valid")
    

    if json_list:
        return json_list
    else:
        return None



def handle_ip(args):

    if(validate(args.ip)):

        return args.ip

    else:

        logger.error( "IP address did not validate " + args.ip )
        return None


def handle_url(args):

    if(validate(args.url)):

        return args.url

    else:

        logger.error( "URL did not validate " + args.url )
        return None

       
def handle_file(args):

    try:

        # filename = os.path.join(os.path.dirname(__file__),str(args.file))
        file = open( str(args.file)  , 'r' )

    except Exception as error:

        logger.exception(str(type(error)))
        logger.exception("ERROR: File Path Not Correct " + args.file)
        os._exit(os.EX_OK)

    else:
 
        with file:

            domain_list = file.read()
            domain_list = domain_list.split("\n")


            if validate(domain_list):

                # Removing any empty strings from the domain
                # Basic input cleaning

                domain_list = list(filter(None, domain_list))
                return domain_list

            else:

                logger.error("List of IPv4 or IPv6 or URLs are in incorrect format")
                return None


def handle_custom(args):

    if validate( str(args.custom) ):

        # This handles both URLs and IPv6 addresses that
        # have a colon in them 

        arguments_ip = args.custom.split(":")
        arguments_ip = ':'.join(arguments_ip[1:])

        return arguments_ip

    else:
        logger.error("Arguments passed to program not valid")
        return None



def argumentparsing(parser):

    # Parsing URLs 
    parser.add_argument('-url', type=str, help="Requires URL ( Google's URL e.g. www.google.com )");
 
    # parser.add_argument('--url-list', type=list, help="Requires a list of URLs 
    # ( Multiple URLs space separated e.g www.google.com www.facebook.com www.twitter.com")
 
    # Parsing IP addresses
    parser.add_argument('-ip', type=str, help="Requires an ip address ( formatting e.g. 127.0.0.1 ) ")

    # Parsing custom input
    parser.add_argument('-custom', type=str, help="Requires a key value pair ( formatting e.g. ipaddress:142.250.207.238 )")

    # Parsing file input
    parser.add_argument('-file',type=str, help="Requires a file name or path to file, with a list of ip addresses, one on each line");

    # Parsing API input
    parser.add_argument('-api',type=str,help="Requires a valid JSON object of the form { \"ipaddress\": \"127.0.0.1\", \"ipaddress\": \"8.8.8.8\" }")

    # Parsing API key
    parser.add_argument("-apikey",type=str,help="Please provide VirusTotal API key")

    args=parser.parse_args()

    # Parsing args and error handling for arguments passed
    # Bootstrapping whoisit for the first time 
    # whoisit.bootstrap(overrides=True)
 
    global apikey

    if( args.apikey != None ):

        apikey = args.apikey

    else:

        logger.error("VirusTotal API key missing, cannot do VirusTotal API requests!!")
        print("VirusTotal API key missing, cannot do VirusTotal API requests!!") 
        os._exit(os.EX_OK)


    if( args.url != None ):

        return handle_url(args)

    elif( args.ip != None ):

        return handle_ip(args)
 
    elif( args.file != None ):

        return handle_file(args)

    elif( args.custom != None ):

        return handle_custom(args)

    elif( args.api != None ):

        return handle_api(args)

    else:

        parser.print_help()


def validate_url(data):
    return True
    '''
    try:

        ip = socket.gethostbyaddr(data)
        logging.info("Resolving "+str(data)+" to host name: " + str(ip))

        return True

    except:
        logging.error("URL not valid or in incorrect format: " + str(data))
        return False

    '''
def validate_ip(data):

    try:

        # Validating the ip address passed as an argument
        # ipaddress.ip_address("ipaddress in valid format")
        # returns a IPV4address or IPV6address object
        # depending on whether the IP address string passed
        # is in a valid format or not otherwise it raises a 
        # ValueError exception 

        ipaddress.ip_address(data)

        return True

    except:

        logger.info("Not in IP address format: " + str(data))
        return False


def validate(data):

    if(type(data) is str):

        data_list=data.split(":")
        if len(data_list) != 1:
            data = ':'.join(data_list[1:])

        #print(data)

        if re.search(r'[a-zA-Z]+',data) is None:

            # If no letters exist then it is an IPv4 address, as 
            # one composed of only numbers

            logger.info("IPv4 address found")

            if validate_ip(data):
                return True
            else:
                return False

        elif re.search(r'([a-f0-9]*\:)+[a-f0-9]*',data) is None and len(data.split(':')) < 4:

            # If no hexadecimal letters in IPv6 format exist in the 
            # IP address or URL as well as more than two colons then 
            # it is an URL or domain

            logger.info("URL found")

            if validate_url(data):
                return True
            else:
                return False

        else: 

            # If hexadecimal letters exist in the correct format and the number
            # of colons is greater than 2 as checked by the split call which 

            logger.info("IPv6 address found")

            if validate_ip(data):
                return True
            else:
                return False


    elif(type(data) is list):

        # Removing any empty strings from the domain
        # Basic input cleaning

        data = list(filter(None, data))

        # In the tool specification it is intimated that there 
        # are going to be list of domain URLs or list of IP addresses
        # thus we could expect a mixed set of IP addresses and domain
        # URLs as well. 

        # In the scenario the list of domains contains some IP addresses
        # we seperate out the IP addresses and create a new list with just 
        # IP addresses

        print("Validating the input domains")

        data_ip = list(filter( validate_ip ,data ))
        data_domain = list(filter(lambda x: not validate_ip(x), data))

        if len(data_ip) == len(data) :

            logger.info("Handling list of all IP addresses here")

            # print(data_ip)
            # return data_ip
 
            return True

        elif len(data_domain) == len(data) :

            logger.info("Handling list of domains or URLs here")
            data_domain_check = list(filter( validate_url,data_domain ))

            if len( data_domain_check ) == len( data_domain ):
                return True
            else:
                logging.error("List of domains was not valid")
                return False     

        elif ( len(data_ip) + len(data_domain) ) == len(data) :

            logger.info("Handling list of mixed IP addresses and domains or URLs") 
            data_domain_check = list(filter( validate_url,data_domain ))

            if len( data_domain_check ) == len( data_domain ):
                return True
            else:
                logging.error("List of domains was not valid")
                return False

        else:
            logger.error("List of domains was not valid")
            return False


def get_hostname(ips):

    if type(ips) is str:
        return socket.gethostbyaddr(ips)[0]

    elif type(ips) is list:
        for ip in ips:
            ips.remove(ip)
            ips.append(socket.gethostbyaddr(ip)[0])
        return ips


async def main():

    # Initializing Argument Parser
    parser = argparse.ArgumentParser(description='A Python-based enrichment tool that gathers information about domains, IP addresses, and URLs using external intelligence sources like WHOIS, VirusTotal, and other open APIs')

    arguments = argumentparsing(parser)   

    # Async handling test of one URL i.e handle_api case -- using 
    # tasks and queues method as described in vt-py package 
    # example scripts currently but want to build something robust 
    # after iterating on this a couple of times

    logger.info( "Domains to queue : " + str(arguments) )
    
    print("Domains to queue: " + str(arguments) )
 
    if arguments == None:
        logging.error("Nothing Queued: Error in arguments passed")
        exit()

    if apikey:
        queue_vt = asyncio.Queue()

    queue_whois = asyncio.Queue()


    # Queuing addresses for VirusTotal API - requires url thus
    # we get the URL for the IP address

    # arguments_vt = get_hostname(arguments)
    asyncio.create_task(queue_addresses(queue_vt,arguments))


    # Queuing addreses in either IPv4 or IPv6 or URL format
    # as python-whois API requests can handle both IP and URLs
    # so we pass the arguments as is

    asyncio.create_task(queue_addresses(queue_whois,arguments))

    # Preparing the output JSON
    vt_json= dict()
    whois_json = dict()

    # Creating worker tasks list
    worker_tasks = []

    # Depending on how many threads we are going to give
    # the Queue to work on it's tasks 

    print("Working to send requests ....")

    for i in range(30) : 
        if apikey:
            worker_tasks.append(asyncio.create_task(async_queue_vt_lookup_url(queue_vt, vt_json)))
        worker_tasks.append(asyncio.create_task(async_queue_whois_lookup(queue_whois, whois_json)))     

    # when all tasks are done
    await asyncio.gather(*worker_tasks)


    # Preparing an output JSON object that is assigned to each 
    # url which will be a key for the output JSON object 

    # Optional 
    # url_json["AbuseIPDB"] = {}
    # url_json["GreyNoise"] = {}
    # url_json["IPinfo" ] = {}

    output_json = dict()

    for key in whois_json.keys():

        url_json = dict()
        url_json["VirusTotal"] = vt_json.get(key)
        url_json["whois"] =  whois_json.get(key)

        output_json[key] = url_json

    # print(json.dumps(output_json, sort_keys = True, indent = 4, default = str))

    # Creating the output file
    
    output_file = "Output_" + str(time.time()) + ".json"

    try:
        with open ( output_file ,"w+" ) as file:
            file.write(json.dumps(output_json, sort_keys = True, indent = 4, default = str))
    except Exception as error:
        logger.exception("Error creating output file " + str(type(error)))
        os._exit(os.EX_OK)

    print("SUCCESS: Result in file " + output_file)

if __name__ == "__main__":
       asyncio.run(main())
