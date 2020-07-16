import os
import logging
import pathlib
import xml.etree.ElementTree as ET 
from os.path import expanduser
import re
import base64
from urllib.parse import urlparse
from zipfile import ZipFile


import requests
from stacker.session_cache import get_session
from stacker.variables import Variable, resolve_variables
from Crypto.Cipher import AES
import hashlib
import botocore
import repositorytools
from troposphere.awslambda import Code

logger = logging.getLogger(__name__)

def _create_cipher(key_bytes, salt_bytes):
  digester = hashlib.sha256()
  spice_len = 16 
  pos = 0
  key_and_iv = []
  key_and_iv_len = spice_len * 2
  result = []
  while(pos < key_and_iv_len):
    digester.update(key_bytes)
    digester.update(salt_bytes)
    result = digester.digest()

    still_need = key_and_iv_len - pos
    # truncate if digest is larger than needed
    if(len(result) > still_need):
      result = result[0:still_need]
    
    key_and_iv[pos:pos+len(result)] = result
    pos += len(result)

    # if more needed, then start next round with hash of hash
    if(pos < key_and_iv_len):
      digester = hashlib.sha256()
      digester.update(result)

  cipher = AES.new(bytes(key_and_iv[0:spice_len]), AES.MODE_CBC, bytes(key_and_iv[spice_len:]))
  return cipher

def _decrypt(key_bytes, cipher_text):
  m = re.search(r'.*?[^\\]?\{(.*?[^\\])\}.*', cipher_text)
  if m:
    cipher_text = m.group(1)
  cipher_bytes = base64.b64decode(cipher_text)
  salt_bytes = cipher_bytes[:8]
  pad_len = cipher_bytes[8]
  enc_bytes = cipher_bytes[9:-pad_len]
  clear_bytes = _create_cipher(key_bytes, salt_bytes).decrypt(enc_bytes)
  return clear_bytes[0:-clear_bytes[-1]]

def _get_maven_master_password(m2_dir=expanduser('~/.m2')):
  tree = ET.parse(f"{m2_dir}/settings-security.xml")
  master_password = tree.getroot().find('./master').text
  return _decrypt(b'settings.security', master_password)

def _get_maven_server_username_password(m2_dir=expanduser('~/.m2'), server_id='nexus'):
  ns = {'mvn': 'http://maven.apache.org/SETTINGS/1.0.0'}
  tree = ET.parse(f"{m2_dir}/settings.xml")
  server = tree.getroot().find(f"./mvn:servers/mvn:server[mvn:id='{server_id}']", ns)
  clear_pass_bytes = _decrypt(_get_maven_master_password(m2_dir), server.find('./mvn:password', ns).text)
  return (server.find('./mvn:username', ns).text, clear_pass_bytes.decode())

def _hash_file(file_path):
  import hashlib
  BLOCKSIZE = 65536
  hasher = hashlib.sha1()
  try:
    with open(file_path, 'rb') as afile:
      buf = afile.read(BLOCKSIZE)
      while len(buf) > 0:
          hasher.update(buf)
          buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()
  except IOError:
    return None

def _download_url(url, username, password):
  file_name = os.path.basename(urlparse(url).path)
  artifact_dir = expanduser(f"~/.stacker/artifacts")
  pathlib.Path(artifact_dir).mkdir(parents=True, exist_ok=True)
  file_path = os.path.join(artifact_dir, file_name)

  file_hash = _hash_file(file_path)
  if file_hash != None:
    file_hash = f"{{SHA1{{{file_hash}}}}}"
  with requests.get(url, auth=(username,  password), stream=True, headers={'If-None-Match': file_hash}) as r:
    r.raise_for_status()
    if r.status_code == 200:
      logger.info(f"download '{url}' to '{file_path}' with current hash '{file_hash}'")
      with open(file_path, 'wb') as f:
        for chunk in r.iter_content(chunk_size=8192):
          f.write(chunk)

  return file_path

def _download_artifact(group_id, artifact_id, version, nexus_url, server_id, repository='releases', extension='jar', classifier=None, **kwargs):
  username, password = _get_maven_server_username_password(server_id=server_id)
  artifact = repositorytools.RemoteArtifact(group_id, artifact_id, version, extension=extension, classifier=classifier, repo_id=repository)
  client = repositorytools.repository_client_factory(repository_url=nexus_url, user=username, password=password)
  client.resolve_artifact(artifact)
  return _download_url(artifact.url, username, password)

def _extract_file(zip_file, path_to_extract):
  file_name = f"{os.path.basename(zip_file)}-{os.path.basename(path_to_extract)}"
  file_path = os.path.join(os.path.dirname(zip_file), file_name)
  with ZipFile(zip_file, 'r') as zip:
    with open(file_path, "wb") as f:
      f.write(zip.read(path_to_extract))
  return file_path

def _head_object(s3_client, bucket, key):
  try:
    return s3_client.head_object(Bucket=bucket, Key=key)
  except botocore.exceptions.ClientError as e:
    if e.response['Error']['Code'] == '404':
      return None
    else:
      raise

def _upload_file(s3_client, path, bucket, prefix=None, acl='private'):
  file_name, file_ext = os.path.splitext(os.path.basename(path))
  file_hash = _hash_file(path)
  key = os.path.join(prefix, f"{file_name}-{file_hash}{file_ext}")

  if _head_object(s3_client, bucket, key):
    logger.debug('object %s already exists, not uploading', key)
  else:
    logger.info(f"upload '{path}' to s3://{bucket}/{key}")
    with open(path, 'rb') as f:
      s3_client.put_object(Bucket=bucket, Key=key, Body=f, ACL=acl)
  return Code(S3Bucket=bucket, S3Key=key)
                      
def _s3_client(context, provider):
  region = context.config.stacker_bucket_region or provider.region
  session = get_session(region)
  return session.client('s3')

def _get_variables(variables, provider, context):
    converted_variables = [
        Variable(k, v) for k, v in variables.items()
    ]
    resolve_variables(
        converted_variables, context, provider
    )
    return {v.name: v.value for v in converted_variables}

def upload_nexus_artifact(context, provider, **kwargs):
  keys = dict()
  variables = _get_variables(kwargs, provider, context)
  for artifact, coords in variables['artifacts'].items():
    coords = _get_variables(coords, provider, context)
    coords['nexus_url'] = variables['nexus_url']
    coords['server_id'] = variables['server_id']
    artifact_path = _download_artifact(**coords)
    if coords.get('zip_path') != None:
      artifact_path = _extract_file(artifact_path, coords['zip_path'])
    code = _upload_file(s3_client=_s3_client(context, provider), path=artifact_path, bucket=variables.get('bucket', context.config.stacker_bucket), prefix=variables.get('prefix', None))
    if variables['data_type'] == 'url':
      region = context.config.stacker_bucket_region or provider.region
      keys[artifact] = f"https://s3-{region}.amazonaws.com/{code.S3Bucket}/{code.S3Key}"
    else:
      keys[artifact] = code.S3Key 
  return keys

def upload_local_artifact(context, provider, **kwargs):
  keys = dict()
  variables = _get_variables(kwargs, provider, context)
  for artifact, artifact_path in variables['artifacts'].items():
    code = _upload_file(s3_client=_s3_client(context, provider), path=artifact_path, bucket=variables.get('bucket', context.config.stacker_bucket), prefix=variables.get('prefix', None))
    if variables['data_type'] == 'url':
      region = context.config.stacker_bucket_region or provider.region
      keys[artifact] = f"https://s3-{region}.amazonaws.com/{code.S3Bucket}/{code.S3Key}"
    else:
      keys[artifact] = code.S3Key 
  return keys


