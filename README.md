Batchsigner for DKIF based Stellar federation service
=======================================================
The batschsigner script was degined to run periodically in docker container (using [Supercronic](https://github.com/aptible/supercronic)). In case one defines the necessary environment variables and installs the necessary dependencies on the host it can run from command line as well. It has been written and tested with Python 2.7.
It does the following:

 - receives its configuration through env variables only (with some sensible defaults)
 - logs in into a host via ssh and find out the IP of the PostgreSQL container
 - sets up an SSH tunnel to the host pointing a local port to the PostgreSQL service
 - logs in into the federation DB and fetches the rows which has the signature column empty (needs signing)
 - selects the entries with row lock (SELECT ... FOR UPDATE;) form the DB one by one, generates the signature of them
   and uploads the signature to the DB

## Docker
You can build your own Docker image (Dockerfile is in the repo) or use our image form dockerhub: lumenbox/batchsigner:latest

## Environment variables used to configure the script
As we run the script in docker container it is receiving it's configuration through environment variables. Here are the variables that you can use to configure the script.
The defaults are defined for our service but can give you a good example to define your own variables.
### LOGLEVEL (Mandatory)
Default: ERROR

This configures the loglevel of the script. Possible values are: ERROR, INFO, DEBUG, WARNING


### PSQL_DOCKER_HOST (Mandatory)
Default: localhost

The hostname for the host which runs the PostgreSQL Docker container


### PSQL_DOCKER_HOST_SSH_PORT (Mandatory)
Default: 22

SSH port of the host which runs the PostgreSQL Docker container

### PSQL_DOCKER_HOST_SSH_USER (Mandatory)
No default

User which will be used to connect to the SSH server on the host which runs the PostgreSQL. The user must be able to run the following command on the host:
```
sudo /usr/bin/docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' CONTAINERNAME
```

### PSQL_DOCKER_HOST_SSH_PWD (Mandatory)
No default

The SSH password. In case this is not empty, it will be used and SSH KEY will be ignored


### PSQL_DOCKER_HOST_SSH_KEY (Optional)
Default: /ssh_key

The path to the SSH KEY inside the batchsigner docker container. One can mount a key from the host into the docker container if necessary.
The key must use a passphrase and the password must be defined in the BATCHSIGNER_PSQL_DOCKER_HOST_SSH_KEY_PWD variable.

IMPORTANT: in case the BATCHSIGNER_PSQL_DOCKER_HOST_SSH_PWD env variable not empty this variable will be ignored


### PSQL_DOCKER_HOST_SSH_KEY_PWD (Optional)
No default

Password for the SSH KEY defined in BATCHSIGNER_PSQL_DOCKER_HOST_SSH_KEY.  In case key based auth is used (BATCHSIGNER_PSQL_DOCKER_HOST_SSH_PWD is empty) this password is mandatory.


### PSQL_DOCKER_HOST_SSH_HOST_KEY (Optional)
No default

We need to define the OpenSSH like host key of the host which runs the postgresql docker container. The script will verify the host key received from the SSH daemon and will exit in case it does not match with this key. The easiest way to get this string is to login to the host via SSH client using the same hostname that you are going to use in the script and copy the proper line from ~/.ssh/known_hosts into this env variable

Example value: example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNJ8faCaeeyEPkjCgitds9V3lWjiRlqEjdPibNXZbvEN1hxrWWyeezZ6IsNiJpzI/qHJXQtYgEgBaLpm0Ou47o0=


### PSQL_DOCKER_CONTAINER_NAME (Mandatory)
No default

The container name of the PostgreSQL. You can get it with ```docker ps``` command on the container host. This name will be used to determine the internal IP of the container


### PSQL_DOCKER_CONTAINER_SERVICE_PORT (Mandatory)
Default: 5432

The service port on which the PostgreSQL container listens


### DB_USER (Mandatory)
No default

The user which will be used to connect to the PostgreSQL DB

### DB_PWD (Mandatory)
No default

The password which will be used to connect to the PostgreSQL DB

### DB_NAME (Mandatory)
No default

Name of the DB in PostgreQL

### DB_UNSIGNED_QUERY (Mandatory)
Default: None

The SELECT statement which will be used to fetch the DB entries which requires signing. With this SELECT we just collect the row id's of these rows so we can go through them one by one, lock and sign them   

Example: "SELECT id FROM account WHERE signature=''"


### DB_SELECT_FOR_UPDATE_QUERY (Mandatory)
Default: None

The python string template of the SELECT ... FOR UPDATE query which is used to select one federation entry for signature calculation. %s in the string will be replaced with the id selected with the BATCHSIGNER_DB_UNSIGNED_QUERY query.
It is important to name the fields properly using the "as" in the query. The fields which are needed for the signature:
* name      : the name part of the federation address
* domain    : the domain part of the federation address
* account   : the Stellar account ID
* memo_type : type of the federation memo
* memo      : federation memo 
* email     : e-mail address of the user who will receive a mail when the signature has been uploaded to the DB

Example: '''SELECT name, domain, account, memo_type, memo, email FROM specialtable WHERE id=%s FOR UPDATE''')

### DB_UPDATE_QUERY (Mandatory)
Default: None

The python string template of the UPDATE statement which will be used to upload the signature to the DB. The first %s will be replaced with the signature and the second %s will be replaced with the id from the BATCHSIGNER_DB_UNSIGNED_QUERY select 

Example: '''UPDATE "account" SET signature=%s WHERE id=%s''')

### DB_CONNECT_OPTIONS (Optional)
Default: "-c statement_timeout=1000"

To set up special db connect options. By default we set the timeout for the queries

### SMTP_HOST (Mandatory)
No default

The SMTP host which will be used to send e-mail to the users. The SMTP server MUST support starttls and must have a valid certificate to do it


### SMTP_USER (Mandatory)
No default

This user will be used to SMTP auth


### SMTP_PWD (Mandatory)
No Default

This password will be used for SMTP auth


### SMTP_SENDER_ADDR (Mandatory)
Default: contact@lumenbox.org

This mail address will be set as sender for the mails which inform the users about their signature 


### SMTP_MSG_SUBJECT (Mandatory)
Default: 'Your federation records have been signed'

Sibject of the mail which is sent to the user when her federation record got signed


### SMTP_MSG_BODY (Mandatory)
Default: 'The following federation records have been signed:\n\r* federation address: %s\n\r* account_id: %s\n\r* memo_type: %s\n\r* memo: %s\n\r\n\rIn case any of the entries above is wrong, please contact us immediately: contact@lumenbox.org\n\r\n\rAll the best,\n\rLumenbox Team')

The python string template for the message body. All the %s will be replaced in the string with the following in order:
* federation address
* stellar account id
* memo_type
* memo


### SECSEED (Mandatory)
No default

The Stellar secret seed which will be used to sined the federation records. One can generate this secret key with any stellar tool which generates stellar accounts like:
* stellar laboratory
* stellar account viewer
* most of the wallets

IMPORTANT: Although it is possible, we DO NOT RECOMMEND to use a valid stellar account's secret seed which may contain lumens


## Signature algorithm which is used to sign the federation record
Let say we have a federation response like the following:
```
{'stellar_address': 'bob*example.com', 'memo_type': 'text', 'account_id': 'GBV5QCPOXI2AU2TKEMDIYUTSXQ7GZ6JZVCKMXV7NDBE3TYKFOJ5KMTHZ', 'memo': 'test'}
```
And we got a Stellar federation secret seed like the following:
```
SBGHL762R7UWD6QDTVNUUFU445DVBS5UANADTL5W56OMW5R2YWUDKWJJ
```

### Get the base64 encoded XDR of the federation record
 - create an object from the AccountID class (generated by XDR) using the KEY_TYPE_ED25519 XDR const and the decoded ed25519 key from account_id:
  ```
  acc = Xdr.types.AccountID(type=Xdr.const.KEY_TYPE_ED25519, ed25519=base64.base32decode('GBV5QCPOXI2AU2TKEMDIYUTSXQ7GZ6JZVCKMXV7NDBE3TYKFOJ5KMTHZ')[1:-2])
  ```
 - create an object from the Memo class (generated by XDR) using the memo_type and the proper parameter based on the memo_type:
  ```
  memo = Xdr.types.Memo(type=Xdr.const.MEMO_TEXT, text='text')
  or
  memo = Xdr.types.Memo(type=Xdr.const.MEMO_ID, id=10000)
  or
  memo = Xdr.types.Memo(type=Xdr.const.MEMO_NONE)
  ```
 - create an object from the FederationResponse class (generated by XDR) (ext is there to follow Stellar federation standard for possible extension):
  ```
  ext = Xdr.nullclass
  ext.v = 0
  fed_rsp = Xdr.types.FederationResponse(stellarAddress='bob*example.com', accountID=acc, memo=memo, ext=ext)
  ```
 - pack the result with Xdr.pack_FederationResponse (generated by XDR):
  ```
  packer = Xdr.federationPacker()
  packer.pack_FederationResponse(fed_rsp) 
  ```
 - get the XDR for signature:
  ```
  packed_fed_rsp = packer.get_buffer()
  ```

### Get the ed25519 signer key from the stellar secret seed
 - decode the stellar secret seed with base32decode:
  ```
  decoded_stellar_seed = base64.b32decode('SBGHL762R7UWD6QDTVNUUFU445DVBS5UANADTL5W56OMW5R2YWUDKWJJ')
  ```
 - cut the unnecessary part of the decoded seed to get the ed25519 seed (1st char is the type of the key and last 2 chars are the CRC):
  ```
  ed25519_seed = decoded_stellar_seed[1:-2]
  ```
 - get the ed25519 signign key from the ed25519 seed using the ed25519 lib:
  ```
  ed25519_signing_key = ed25519.SigningKey(ed25519_seed)
  ```
  
### Sign the federation XDR with the signing key and encode it with base64
 - create a sha256 digest from the base64 encoded federation XDR:
  ```
  sha_fed_rsp = hashlib.sha256(packed_fed_rsp).digest()
  ```
 - sign the sha256 digest using the ed25519 signing key:
  ```
  signed_fed_rsp = ed25519_signing_key.sign(sha_fed_rsp)
  ```
 - get the final signature with encoding the signed federation respons using base64:
  ```
  signature = base64.b64encode(signed_fed_rsp)
  ```
