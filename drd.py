import argparse
import requests
import json
import os

API_VERSION   = "v2"
repositories  = []
tags          = []
blob          = []
AUTH          = False
username      = ""
password      = ""

parser = argparse.ArgumentParser()
parser.add_argument("-url", dest="url", required=True, help="Docker registry URL, ex: docker.example.com")
parser.add_argument("-user", dest="username", required=False, help="Authentification username")
parser.add_argument("-pass", dest="password", required=False, help="Authentification password")
parser.add_argument("-lrp", dest="list_repos", action="store_true", required=False, help="List repositories")
parser.add_argument("-lb", dest="list_blobs", action="store_true", required=False, help="List blobs of a tag")
parser.add_argument("-lt", dest="list_tags", action="store_true", required=False, help="List tags of a repository")
parser.add_argument("-repo", dest="repo", required=False, help="Target a repository")
parser.add_argument("-tag", dest="tag", required=False, help="Target a tag of a repository")
parser.add_argument("-blob", dest="blob", required=False, help="Target a blob of a tag")
parser.add_argument("-ab", dest="ab", action="store_true", required=False, help="Get all blobs")
parser.add_argument("-dest", dest="dest", required=False, help="Destination directory, default = CURRENT DIR", default="./")


args = parser.parse_args()
url = args.url
if args.username :
    if args.password:
        AUTH     = True
        username = args.username
        password = args.password
    else :
        print("[!] Password not specified.")
else :
    if args.password:
        print("[!] Username not specified.")
    else:
        pass

def test_target(url):
    url = "{}/{}".format(url, API_VERSION)
    if AUTH :
        r = requests.get(url, auth=requests.auth.HTTPBasicAuth(username, password))
        if r.status_code == 200 :
            print("[*] {} is UP !\n\n".format(url))
            return True
        elif r.status_code == 401 :
            print("[!] Bad credentials.")
            return False
        else :
            print("[!] Something went wrong with the server.")
            return False
    else :
        r = requests.get(url)
        if r.status_code == 200 :
            print("[+] {} is UP !".format(url))
            return True
        elif r.status_code == 401 :
            print("[!] You need some credentials.")
            return False
        else :
            print("[!] Something went wrong with the server.")
            return False

def list_repos(url):
    url = "{}/{}/_catalog".format(url, API_VERSION)
    r = requests.get(url, auth=requests.auth.HTTPBasicAuth(username, password))
    json_data = r.json()
    if "repositories" in json_data :
        return json_data['repositories']
    else :
        return []

def list_tags(url, repo):
    url = "{}/{}/{}/tags/list".format(url, API_VERSION, repo)
    r = requests.get(url, auth=requests.auth.HTTPBasicAuth(username, password))
    json_data = r.json()
    if "tags" in json_data :
        return json_data['tags']
    else :
        return []


def list_blobs(url, repo, tag):
    url = "{}/{}/{}/manifests/{}".format(url, API_VERSION, repo, tag)
    r = requests.get(url, auth=requests.auth.HTTPBasicAuth(username, password))
    json_data = r.json()
    if "fsLayers" in json_data :
        if len(json_data["fsLayers"]) > 0 :
            tmp = []
            for blob in json_data["fsLayers"] :
                tmp.append(blob['blobSum'])
            return tmp

    return []

def get_blob(url, repo, tag, blob, dirpath) :
    url  = "{}/{}/{}/blobs/{}".format(url, API_VERSION, repo, blob)
    r = requests.get(url, auth=requests.auth.HTTPBasicAuth(username, password))
    file_name = "{}.tar.gz".format(blob.strip("sha256:"))
    with open(dirpath+"/"+file_name, 'wb') as file :
        file.write(r.content)


def main():
    if test_target(url) :
        if args.list_repos :
            print("[*] Listing repositories...")
            repositories = list_repos(url)
            if len(repositories) > 0 :
                for repo in repositories :
                    print("\t[+] {}".format(repo))
            else :
                print("[!] No repository found :(")
                exit(1)
        if args.list_tags :
            if args.repo :
                repo = args.repo
                repositories = list_repos(url)
                if repo in repositories :
                    print("[*] Listing tags...")
                    tags = list_tags(url, repo)
                    if len(tags) > 0 :
                        for tag in tags :
                            print("\t[+] {}".format(tag))
                    else :
                        print("[!] No tag found :(")
                        exit(1)
            else :
                print("\n\n[!] You have to specify a repo using -repo")
                exit(1)

        if args.repo and args.tag and args.blob is None :
            repo = args.repo 
            tag  = args.tag
            repositories = list_repos(url)
            if repo in repositories :
                tags = list_tags(url, repo)
                if tag in tags :
                    print("[*] Listing blobs...")
                    blobs = list_blobs(url, repo, tag)
                    if len(blobs) > 0 :
                        for blob in blobs :
                            print("\t[+] {}".format(blob))
                    else :
                        print("[!] No blob found :(")
                        exit(1)
                else :
                    print("[!] Invalid tag name.")
                    exit(1)
            else :
                print("[!] Invalid repository name.")
                exit(1)

        if args.repo and args.tag and (args.blob or args.ab):
            repo = args.repo 
            tag  = args.tag
            blob = args.blob
            dest = "{}/{}/{}/".format(args.dest,repo,tag)
            repositories = list_repos(url)
            if repo in repositories :
                tags = list_tags(url, repo)
                if tag in tags :
                    blobs = list_blobs(url, repo, tag)
                    if len(blobs) > 0 :
                        if args.ab :
                            os.makedirs(dest, exist_ok=True)
                            for b in blobs :
                                print("[+] Getting {}".format(b))
                                get_blob(url, repo, tag, b, dest)
                        else :
                            if blob in blobs :
                                os.makedirs(dest, exist_ok=True)
                                print("[+] Getting {}".format(blob))
                                get_blob(url, repo, tag, blob, dest)
                            else :
                                print("[!] Invalid blob, you can check with -lb")
                                exit(1)
                else :
                    print("[!] Invalid tag name, you can check with -lt")
                    exit(1)
            else :
                print("[!] Invalid repository name, you can check with -lrp")
                exit(1)











                








if __name__ == "__main__" :
    main()