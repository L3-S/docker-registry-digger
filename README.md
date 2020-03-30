# docker-registry-digger
A simple python3 script for pulling docker images from a docker registry
<pre>
usage: drd.py [-h] -url URL [-user USERNAME] [-pass PASSWORD] [-lrp]
              [-lb LIST_BLOBS] [-lt] [-repo REPO] [-tag TAG] [-blob BLOB]
              [-ab] [-dest DEST]

optional arguments:
  -h, --help      show this help message and exit
  -url URL        Docker registry URL, ex: docker.example.com
  -user USERNAME  Authentification username
  -pass PASSWORD  Authentification password
  -lrp            List repositories
  -lb LIST_BLOBS  List blobs of a tag
  -lt             List tags of a repositories
  -repo REPO      Target a repository
  -tag TAG        Target a tag of a repository
  -blob BLOB      Target a blob of a tag
  -ab             Get all blobs
  -dest DEST      Destination directory, default = CURRENT DIR
</pre>
