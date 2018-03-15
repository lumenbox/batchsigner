#!/usr/bin/env python
# -*- coding: utf-8 -*-

from federationxdr import Xdr
import paramiko
from sshtunnel import SSHTunnelForwarder
import sys
import log
import base64
import logging
import hashlib
import ed25519
import os
import ipaddress
import psycopg2
import smtplib
from email.mime.text import MIMEText

__version__ = "0.1.0"

config = {'LOGLEVEL': os.getenv('LOGLEVEL', 'ERROR')}

# set up logging
log_map = {'ERROR': logging.ERROR, 'INFO': logging.INFO, 'DEBUG': logging.DEBUG, 'WARNING': logging.WARNING}
try:
    logger = log.setup_custom_logger('batchsigner', log_map[config['LOGLEVEL']])
except KeyError:
    print('LogLevel is set to %s but it must be one of the following values: %s' % (config['LOGLEVEL'], log_map.keys()))
    sys.exit(1)

# fetch mandatory env
for one_env in ['PSQL_DOCKER_HOST_SSH_USER', 'PSQL_DOCKER_HOST_SSH_USER', 'PSQL_DOCKER_CONTAINER_NAME', 'DB_USER', 'DB_PWD',
            'DB_NAME', 'DB_UNSIGNED_QUERY', 'DB_SELECT_FOR_UPDATE_QUERY', 'DB_UPDATE_QUERY', 'SMTP_HOST', 'SMTP_USER',
            'SMTP_PWD', 'SMTP_SENDER_ADDR', 'SECSEED']:
    try:
        config[one_env] = os.environ[one_env]
    except KeyError:
        logger.error('%s environment variable is mandatory' % one_env)
        sys.exit(1)

# fetch env with defaults
for one_env in [('PSQL_DOCKER_HOST', 'localhost'), ('PSQL_DOCKER_HOST_SSH_PORT', '22'),
                ('PSQL_DOCKER_HOST_SSH_PWD', None), ('PSQL_DOCKER_HOST_SSH_KEY', '/ssh_key'),
                ('PSQL_DOCKER_HOST_SSH_KEY_PWD', None), ('PSQL_DOCKER_HOST_SSH_HOST_KEY', None),
                ('PSQL_DOCKER_CONTAINER_SERVICE_PORT', '5432'), ('DB_CONNECT_OPTIONS', "-c statement_timeout=1000"),
                ('SMTP_MSG_SUBJECT', 'Your federation records have been signed'),
                ('SMTP_MSG_BODY', 'The following federation records have been signed:\n\r* federation address: %s\n\r* account_id: %s\n\r* memo_type: %s\n\r* memo: %s\n\r\n\rIn case any of the entries above is wrong, please contact us immediately: contact@lumenbox.org\n\r\n\rAll the best,\n\rLumenbox Team')]:
    config[one_env[0]] = os.getenv(one_env[0], one_env[1])

paramiko_class_map = {'ecdsa-sha2-nistp256': paramiko.ecdsakey.ECDSAKey,
                      'ecdsa-sha2-nistp384': paramiko.ecdsakey.ECDSAKey,
                      'ecdsa-sha2-nistp521': paramiko.ecdsakey.ECDSAKey,
                      'ssh-rsa': paramiko.rsakey.RSAKey,
                      'ssh-dss': paramiko.dsskey.DSSKey,
                      'ssh-ed25519': paramiko.ed25519key.Ed25519Key
                      }


class AccountID(object):
    def __init__(self, account_id):
        self._account_id = account_id

    def __str__(self):
        return 'account id: %s' % self._account_id

    @property
    def _ed25519_key(self):
        # todo: verify is the key is a proper ed25519 key
        return base64.b32decode(self._account_id)[1:-2]

    @property
    def xdr_object(self):
        ret = Xdr.types.AccountID(Xdr.const.KEY_TYPE_ED25519, self._ed25519_key)
        logger.debug('accountID for XDR encoding: %s' % ret)
        return ret


class Memo(object):
    def __init__(self, memo_type=None, memo=None):
        self._memo = memo
        self._memo_type = memo_type
        self._memo_type_dict = {None: {'type': Xdr.const.MEMO_NONE},
                                '': {'type': Xdr.const.MEMO_NONE},
                                'MEMO_ID': {'type': Xdr.const.MEMO_ID, 'id': self._memo},
                                'MEMO_TEXT': {'type': Xdr.const.MEMO_TEXT, 'text': self._memo},
                                'MEMO_HASH': {'type': Xdr.const.MEMO_HASH, 'hash': self._memo}}

    def __str__(self):
        return 'memo_type: %s memo: %s' % (self._memo_type, self._memo)

    @property
    def xdr_object(self):
        try:
            memo_dict = self._memo_type_dict[self._memo_type]
        except KeyError:
            raise ValueError(
                'memo_type is %s but must be one of the following: %s' % (self._memo_type, self._memo_type_dict.keys()))
        if memo_dict['type'] == Xdr.const.MEMO_ID:
            try:
                memo_dict['id'] = int(memo_dict['id'])
            except ValueError:
                raise ValueError('memo_type is id but "%s" memo cannot be converted to integer' % self._memo)
        ret = Xdr.types.Memo(**memo_dict)
        logger.debug('memo for XDR encoding: %s' % ret)
        return ret


class FederationResponse(object):
    def __init__(self, stellar_address, account_id, memo_type=None, memo=None):
        self._stellar_address = stellar_address
        self._account_id = AccountID(account_id)
        self._memo = Memo(memo_type, memo)

    def __str__(self):
        return 'stellar_address: %s %s %s' % (self._stellar_address, self._account_id, self._memo)

    @property
    def xdr_object(self):
        ext = Xdr.nullclass
        ext.v = 0
        return Xdr.types.FederationResponse(self._stellar_address, self._account_id.xdr_object, self._memo.xdr_object,
                                            ext)

    @property
    def xdr(self):
        fedresp = Xdr.federationPacker()
        fedresp.pack_FederationResponse(self.xdr_object)
        packed_xdr = fedresp.get_buffer()
        logger.debug('base64 encoded federation response xdr: %s' % base64.b64encode(packed_xdr))
        return packed_xdr


# todo: get rid of this Signer class and create a signature property for the FederationResponse class
class Signer(object):
    def __init__(self, data, stellar_secret_seed):
        self._data = data
        self._stellar_secret_seed = stellar_secret_seed

    @property
    def _ed25519_seed(self):
        decoded_stellar_seed = base64.b32decode(self._stellar_secret_seed)
        return decoded_stellar_seed[1:-2]

    @property
    def _signing_key(self):
        return ed25519.SigningKey(self._ed25519_seed)

    @property
    def signature(self):
        sig = base64.b64encode(self._signing_key.sign(hashlib.sha256(self._data).digest()))
        return sig


class Tunnel(object):
    def __init__(self, host, user_name, container_name, container_service_port, port=22, pwd=None, key=None,
                 key_pwd=None, host_key=None):
        self._host_key_str = host_key
        self._host_key = None
        self._host_key_hostname = None
        self._container_name = container_name
        self._pwd = pwd
        self._key = key
        self._key_pwd = key_pwd
        self._user_name = user_name
        self._host = host
        self._using_key = None
        self._container_ip = None
        self._tunnel = None
        try:
            self._container_service_port = int(container_service_port)
        except ValueError:
            raise ValueError('the received container service port %s is not an integer' % container_service_port)

        try:
            self._port = int(port)
        except ValueError:
            raise ValueError('the received port "%s" is not an integer' % port)

        self._parse_host_key_string()

        self._parameters_for_paramiko_client = {'hostname': self._host, 'port': self._port, 'username': self._user_name,
                                                'look_for_keys': False}
        self._parameters_for_ssh_tunnel = {'ssh_address_or_host': (self._host, self._port),
                                           'ssh_username': self._user_name, 'local_bind_address': ('127.0.0.1',),
                                           'ssh_host_key': self._host_key}
        self._key_or_pwd()
        self._get_container_ip()
        self._create_tunnel()
        logger.debug("created SSH tunnel to the container using localhost port %s" % self.local_bind_port)

    def _parse_host_key_string(self):
        try:
            self._host_key_hostname = self._host_key_str.split(' ')[0]
            host_key_type = self._host_key_str.split(' ')[1]
            host_key_data = self._host_key_str.split(' ')[2]
        except KeyError:
            raise ValueError(
                'The host key string must look like an entry in the known_hosts file. Received: %s' % self._host_key_str)
        try:
            self._host_key = paramiko_class_map[host_key_type](data=base64.b64decode(host_key_data))
        except KeyError:
            raise ValueError('Unknown host key type %s. Possible values: %s' % (
                self._host_key_str.split(' ')[1], paramiko_class_map.keys()))

    def _key_or_pwd(self):
        if self._key is not None and self._key_pwd is not None:
            self._using_key = True
            self._parameters_for_paramiko_client['key_filename'] = self._key
            self._parameters_for_paramiko_client['pkey'] = self._key_pwd
            self._parameters_for_ssh_tunnel['ssh_pkey'] = self._key
            self._parameters_for_ssh_tunnel['ssh_private_key_password'] = self._key_pwd
            logger.debug('connecting to %s@%s on port %s with %s key to get the ip of %s container' % (
                self._user_name, self._host, self._port, self._key, self._container_name))
        elif self._pwd is not None:
            self._using_key = False
            self._parameters_for_paramiko_client['password'] = self._pwd
            self._parameters_for_ssh_tunnel['ssh_password'] = self._pwd
            logger.debug('connecting to %s@%s on port %s using password to get the ip of %s container' % (
                self._user_name, self._host, self._port, self._container_name))
        else:
            raise ValueError('Either password or key+key_password is mandatory')

    def _get_container_ip(self):
        with paramiko.SSHClient() as client:
            # clear host keys and add host key from env
            host_keys = client.get_host_keys()
            host_keys.clear()
            logger.debug('adding %s host key for %s host' % (self._host_key.get_name(), self._host_key_hostname))
            host_keys.add(hostname=self._host_key_hostname, keytype=self._host_key.get_name(), key=self._host_key)

            try:
                client.connect(**self._parameters_for_paramiko_client)
            except paramiko.ssh_exception.AuthenticationException as e:
                raise ValueError('auth to the host was not successful: %s' % e)

            command = '''sudo /usr/bin/docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s''' % self._container_name
            (stdin, stdout, stderr) = client.exec_command(command)
            if stdout.channel.recv_exit_status() != 0:
                raise LookupError('docker command return value was %s. Error line were: %s' % (
                    stdout.channel.recv_exit_status(), stderr.readlines()))

            self._container_ip = stdout.readlines()[0].rstrip('\n')
            self._parameters_for_ssh_tunnel['remote_bind_address'] = (self._container_ip, self._container_service_port)

        try:
            ipaddress.ip_address(self._container_ip)
            logger.debug('the ip of the "%s" container is "%s"' % (self._container_name, self._container_ip))
        except ValueError:
            raise LookupError(
                'received "%s" as IP address for the %s container' % (self._container_ip, self._container_name))

    def _create_tunnel(self):
        self._tunnel = SSHTunnelForwarder(**self._parameters_for_ssh_tunnel)
        self._tunnel.start()

    @property
    def local_bind_host(self):
        return self._tunnel.local_bind_host

    @property
    def local_bind_port(self):
        return self._tunnel.local_bind_port

    def close(self):
        self._tunnel.close()


class DB(object):
    def __init__(self, host, user_name, pwd, db_name, connect_options, unsigned_query, select_for_update_query,
                 update_query, port=5432):
        self._host = host
        self._user_name = user_name
        self._pwd = pwd
        self._db_name = db_name
        self._conn = None
        self._cur = None
        try:
            self._port = int(port)
        except ValueError:
            raise ValueError('the received DB port "%s" is not an integer' % port)
        self._unsigned_query = unsigned_query
        self._select_for_update_query = select_for_update_query
        self._update_query = update_query
        self._db_connect_options = connect_options

        self._get_connection()

    def _get_connection(self):
        try:
            self._conn = psycopg2.connect(dbname=self._db_name, user=self._user_name, host=self._host, port=self._port,
                                          password=self._pwd, options=self._db_connect_options)
            logger.debug(
                'Connected to %s DB on %s@%s using %s port' % (self._db_name, self._user_name, self._host, self._port))
        except Exception as e:
            raise ValueError('could not create connection to %s DB on %s@%s using %s port. Error was: %s' % (
                self._db_name, self._user_name, self._host, self._port, e))

    @property
    def unsigned_accounts(self):
        self._conn.set_session(readonly=True, autocommit=True)
        with self._conn.cursor() as cursor:
            cursor.execute(self._unsigned_query)
            # we do not expect millions of unsigned users so fetchall should just work fine
            result = cursor.fetchall()
            logger.debug('%s account is missing signature' % len(result))
            self._conn.set_session(readonly=False, autocommit=False)
            return result

    def get_signature_data_for_one_user(self, acc_id):
        self._cur = self._conn.cursor()
        self._cur.execute(self._select_for_update_query, acc_id)
        colnames = [desc[0] for desc in self._cur.description]
        ret_dict = {}
        user_records = self._cur.fetchone()
        for index, item in enumerate(colnames):
            ret_dict[item] = user_records[index]
        logger.debug('received the following unsigned user records: %s' % ret_dict)
        return ret_dict

    def upload_signature(self, sig, acc_id):
        logger.debug('Uploading %s signature to user with id %s' % (sig, acc_id[0]))
        self._cur.execute(self._update_query, (sig, acc_id[0]))
        self._conn.commit()
        self._cur.close()

    def close(self):
        self._conn.close()


class Mailer(object):
    def __init__(self, smtp_host, smtp_user, smtp_pwd, subject, sender_address):
        self._smtp_host = smtp_host
        self._smtp_user = smtp_user
        self._smtp_pwd = smtp_pwd
        self._subject = subject
        self._sender_address = sender_address
        self._smtp = None

        self._set_up_smtp_connection()

    def _set_up_smtp_connection(self):
        self._smtp = smtplib.SMTP(self._smtp_host)
        self._smtp.starttls()
        self._smtp.login(user=self._smtp_user, password=self._smtp_pwd)

    def send(self, msg_body, to_address):
        msg = MIMEText(msg_body)
        msg['Subject'] = self._subject
        msg['From'] = self._sender_address
        msg['To'] = to_address
        self._smtp.sendmail(from_addr=self._sender_address, to_addrs=[to_address], msg=msg.as_string())

    def close(self):
        self._smtp.quit()


if __name__ == '__main__':

    # ToDo: nicer exception handling
    try:
        ssh_tunnel = Tunnel(host=config['PSQL_DOCKER_HOST'], port=config['PSQL_DOCKER_HOST_SSH_PORT'],
                            user_name=config['PSQL_DOCKER_HOST_SSH_USER'], pwd=config['PSQL_DOCKER_HOST_SSH_PWD'],
                            container_name=config['PSQL_DOCKER_CONTAINER_NAME'],
                            container_service_port=config['PSQL_DOCKER_CONTAINER_SERVICE_PORT'],
                            host_key=config['PSQL_DOCKER_HOST_SSH_HOST_KEY'])
    except Exception as e:
        logger.error('Error creating the ssh tunnel. Error was: %s' % e)
        sys.exit(1)

    # ToDo: nicer exception handling
    try:
        db = DB(host=ssh_tunnel.local_bind_host, user_name=config['DB_USER'], pwd=config['DB_PWD'],
                db_name=config['DB_NAME'], unsigned_query=config['DB_UNSIGNED_QUERY'],
                select_for_update_query=config['DB_SELECT_FOR_UPDATE_QUERY'], update_query=config['DB_UPDATE_QUERY'],
                connect_options=config['DB_CONNECT_OPTIONS'], port=ssh_tunnel.local_bind_port)
    except Exception as e:
        logger.error('Error creating the DB connection. Error was: %s' % e)
        ssh_tunnel.close()
        sys.exit(1)

    # ToDo: nicer exception handling
    try:
        mailer = Mailer(smtp_host=config['SMTP_HOST'], smtp_user=config['SMTP_USER'], smtp_pwd=config['SMTP_PWD'],
                        subject=config['SMTP_MSG_SUBJECT'], sender_address=config['SMTP_SENDER_ADDR'])
    except Exception as e:
        logger.error('Error creating the SMTP connection. Error was: %s' % e)
        ssh_tunnel.close()
        db.close()
        sys.exit(1)

    for one_user_id in db.unsigned_accounts:
        user_dict = db.get_signature_data_for_one_user(one_user_id)
        fed_dict = {'stellar_address': '%s*%s' % (user_dict['name'], user_dict['domain']),
                    'memo_type': user_dict['memo_type'], 'account_id': user_dict['account'], 'memo': user_dict['memo']}
        # ToDo: nicer exception handling
        try:
            db.upload_signature(Signer(FederationResponse(**fed_dict).xdr, config['SECSEED']).signature, one_user_id)
        except Exception as e:
            logger.error(
                'could not sign or upload the records of %s trying to continue with the next one. Error was: %s' % (
                    fed_dict, e))
            continue
        logger.debug("sending e-mail to %s about signing record for %s*%s stellar address" % (user_dict['email'],
                                                                                              user_dict['name'],
                                                                                              user_dict['domain']))
        mailer.send(msg_body=config['SMTP_MSG_BODY'] % (
            '%s*%s' % (user_dict['name'], user_dict['domain']), user_dict['account'], user_dict['memo_type'],
            user_dict['memo']), to_address=user_dict['email'])

    mailer.close()
    db.close()
    ssh_tunnel.close()
